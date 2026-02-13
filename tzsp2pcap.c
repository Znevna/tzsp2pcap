/*
 * tzsp2pcap for Windows & Wireshark Extcap
 * Fixed for MinGW/MSYS2 compilation
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <ctype.h>

/* --- Windows Compatibility Layer --- */
#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <windows.h>
	#include <process.h> /* For _spawnlp */
	#include <io.h>
	
	/* MinGW/MSYS2 specific includes for command line parsing */
	#include <unistd.h>
	#include <getopt.h>

	/* Windows mappings for standard POSIX functions */
	#define close closesocket
	#define sleep(x) Sleep((x)*1000)
	
	#ifndef PATH_MAX
		#define PATH_MAX MAX_PATH
	#endif

	/* Windows does not have gettimeofday, so we implement a shim for PCAP timestamps */
	static int gettimeofday(struct timeval *tv, void *tz) {
		(void)tz; /* Fix unused parameter warning */
		if (tv) {
			FILETIME ft;
			unsigned __int64 tmpres = 0;

			/* Optimization: Try to load high-precision timer (Win8+) */
			static void (WINAPI *pGetSystemTimePreciseAsFileTime)(LPFILETIME) = NULL;
			static int tried_loading = 0;

			if (!tried_loading) {
				HMODULE hKernel = GetModuleHandleA("kernel32.dll");
				if (hKernel) {
					/* FIX: Use a union to cast function pointers without violating strict ISO C rules */
					union {
						FARPROC fp;
						void (WINAPI *func)(LPFILETIME);
					} caster;
					
					caster.fp = GetProcAddress(hKernel, "GetSystemTimePreciseAsFileTime");
					pGetSystemTimePreciseAsFileTime = caster.func;
				}
				tried_loading = 1;
			}

			if (pGetSystemTimePreciseAsFileTime) {
				pGetSystemTimePreciseAsFileTime(&ft);
			} else {
				GetSystemTimeAsFileTime(&ft);
			}

			tmpres |= ft.dwHighDateTime;
			tmpres <<= 32;
			tmpres |= ft.dwLowDateTime;
			tmpres /= 10;
			tmpres -= 11644473600000000ULL; /* Convert 1601 epoch to 1970 epoch */
			tv->tv_sec = (long)(tmpres / 1000000UL);
			tv->tv_usec = (long)(tmpres % 1000000UL);
		}
		return 0;
	}

	/* Windows does not have localtime_r, use the thread-safe standard C equivalent */
	static struct tm *localtime_r(const time_t *timer, struct tm *buf) {
		if (localtime_s(buf, timer) == 0) return buf;
		return NULL;
	}

#else
	/* Original POSIX Includes */
	#include <arpa/inet.h> /* For inet_pton */
	#include <sys/wait.h>
	#include <sys/param.h>
	#include <unistd.h>
	#include <sys/socket.h>
	#include <sys/select.h>
	#include <netinet/in.h>
	#include <sys/time.h>
	#include <sys/resource.h>
	#include <getopt.h> /* Ensure getopt_long is available on Linux too */
#endif
/* --- End Windows Compatibility Layer --- */

#include <pcap/pcap.h>

#define ARRAYSZ(x) (sizeof(x)/sizeof(*x))

/* Named constants for TZSP encapsulation types */
#define TZSP_ENCAP_ETHERNET           1
#define TZSP_ENCAP_802_11             2
#define TZSP_ENCAP_802_11_PRISM       3
#define TZSP_ENCAP_802_11_AVS         4
#define TZSP_ENCAP_802_11_RADIOTAP    5

#define DEFAULT_RECV_BUFFER_SIZE 65535
#define DEFAULT_LISTEN_PORT 37008
#define DEFAULT_OUT_FILENAME "-"

// constants

#define TZSP_TYPE_RECEIVED_TAG_LIST 0
#define TZSP_TYPE_PACKET_FOR_TRANSMIT 1
#define TZSP_TYPE_RESERVED 2
#define TZSP_TYPE_CONFIGURATION 3
#define TZSP_TYPE_KEEPALIVE 4
#define TZSP_TYPE_PORT_OPENER 5

static const char * const tzsp_type_names[] = {
	[TZSP_TYPE_RECEIVED_TAG_LIST]   = "RECEIVED_TAG_LIST",
	[TZSP_TYPE_PACKET_FOR_TRANSMIT] = "PACKET_FOR_TRANSMIT",
	[TZSP_TYPE_RESERVED]            = "RESERVED",
	[TZSP_TYPE_CONFIGURATION]       = "CONFIGURATION",
	[TZSP_TYPE_KEEPALIVE]           = "KEEPALIVE",
	[TZSP_TYPE_PORT_OPENER]         = "PORT_OPENER",
};

#define TZSP_TAG_END 1
#define TZSP_TAG_PADDING 0

static const char * const tzsp_tag_names[] = {
	[TZSP_TAG_END]     = "END",
	[TZSP_TAG_PADDING] = "PADDING",
};

struct tzsp_header {
	uint8_t version;
	uint8_t type;
	uint16_t encap;
} __attribute__((packed));

struct tzsp_tag {
	uint8_t type;
	uint8_t length;
	char  data[];
} __attribute__((packed));

/**
 * Application instance type
 */
struct my_pcap_t {
	pcap_t *pcap;

	const char *filename_template;
	const char *filename;

	pcap_dumper_t *dumper;
	FILE *fp;               // dumper's underlying file

	int verbose;

	int rotation_interval;
	time_t rotation_start_time;
	int rotation_size_threshold;
	int rotation_count;
	const char *postrotate_command;
};

#ifndef _WIN32
static int self_pipe_fds[2] = { -1, -1 };
#endif

/* Flags modified only in signal handlers; read in main loop. */
static volatile sig_atomic_t terminate_requested = 0;
static volatile sig_atomic_t child_exited = 0;
static volatile sig_atomic_t shutting_down = 0;

/* Global handle to keep the pipe open across DLT rotations */
static FILE *g_fifo_handle = NULL;

static void request_terminate_handler(int signum) {
	(void)signum;

	/* Just record the request and wake the main loop. */
	terminate_requested = 1;

#ifndef _WIN32
	/* Linux: Write to pipe to wake select() */
	char data = 0;
	if (self_pipe_fds[1] >= 0 && !shutting_down) {
		ssize_t r = write(self_pipe_fds[1], &data, sizeof(data));
		if (r == -1) {
			/* Transient/expected failures (EAGAIN/EWOULDBLOCK/EINTR): drop notification. */
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				/* Irrecoverable error on the pipe: close it to avoid repeated failures. */
				int saved_errno = errno;
				close(self_pipe_fds[1]);
				self_pipe_fds[1] = -1;
				errno = saved_errno;
			}
		}
	}
#endif
}

static int setup_tzsp_listener(uint16_t listen_port, const char *listen_addr) {
	int sockfd = -1;
	int result;
	
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	void *bind_addr_ptr = NULL;
	socklen_t bind_addr_len = 0;
	int domain = AF_INET6; // Default to IPv6 for wildcard

	// 1. Determine Address Family and Parse IP
	if (listen_addr && strlen(listen_addr) > 0) {
	/* Try IPv4 */
	memset(&addr4, 0, sizeof(addr4));
	if (inet_pton(AF_INET, listen_addr, &addr4.sin_addr) == 1) {
		domain = AF_INET;
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(listen_port);
		bind_addr_ptr = &addr4;
		bind_addr_len = sizeof(addr4);
	}
	/* Try IPv6 */
	else {
		memset(&addr6, 0, sizeof(addr6));
		if (inet_pton(AF_INET6, listen_addr, &addr6.sin6_addr) == 1) {
			domain = AF_INET6;
			addr6.sin6_family = AF_INET6;
			addr6.sin6_port = htons(listen_port);
			bind_addr_ptr = &addr6;
			bind_addr_len = sizeof(addr6);
		}
		else {
			fprintf(stderr, "Invalid IP address format: %s\n", listen_addr);
			return -1;
		}
	}
} else {
		// Default: Wildcard IPv6 (Dual Stack)
		domain = AF_INET6;
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(listen_port);
		addr6.sin6_addr = in6addr_any;
		bind_addr_ptr = &addr6;
		bind_addr_len = sizeof(addr6);
	}

	// 2. Create Socket
	#if defined(SOCK_CLOEXEC) && !defined(_WIN32)
		sockfd = socket(domain, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	#else
		sockfd = (int)socket(domain, SOCK_DGRAM, IPPROTO_UDP);
	#endif

	if (sockfd == -1) {
		perror("socket()");
		return -1;
	}

	// 3. Configure Socket Options
	#if !defined(SOCK_CLOEXEC) && !defined(_WIN32)
		int fdflags = fcntl(sockfd, F_GETFD, 0);
		if (fdflags != -1) fcntl(sockfd, F_SETFD, fdflags | FD_CLOEXEC);
	#endif

	// Handle Dual-Stack for IPv6
	if (domain == AF_INET6) {
		/* * If binding to a specific IPv6 address (e.g., ::1), we strictly use IPv6 (v6only=1).
		 * If binding to wildcard (NULL), we allow Dual Stack (v6only=0) to receive IPv4-mapped packets.
		 */
		int v6only = (listen_addr && strlen(listen_addr) > 0) ? 1 : 0;
		
		#ifdef _WIN32
		result = setsockopt((SOCKET)sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&v6only, sizeof(v6only));
		#else
		result = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&v6only, sizeof(v6only));
		#endif
		
		if (result == -1) {
			perror("setsockopt(IPV6_V6ONLY)");
			#ifdef _WIN32
			closesocket((SOCKET)sockfd);
			#else
			close(sockfd);
			#endif
			return -1;
		}
	}

	// 4. Bind
	#ifdef _WIN32
	result = bind((SOCKET)sockfd, (struct sockaddr*) bind_addr_ptr, bind_addr_len);
	#else
	result = bind(sockfd, (struct sockaddr*) bind_addr_ptr, bind_addr_len);
	#endif
	
	if (result == -1) {
		perror("bind()");
		fprintf(stderr, "Failed to bind to %s port %u\n", 
			listen_addr ? listen_addr : "any", listen_port);
		
		#ifdef _WIN32
		closesocket((SOCKET)sockfd);
		#else
		close(sockfd);
		#endif
		return -1;
	}

	return sockfd;
}

static void cleanup_tzsp_listener(int socket) {
	/* Warning fix: cast to SOCKET */
	#ifdef _WIN32
	close((SOCKET)socket);
	#else
	close(socket);
	#endif
}

static void trap_signal(int signum) {
#ifdef _WIN32
	signal(signum, request_terminate_handler);
#else
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = request_terminate_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	struct sigaction old;
	if (sigaction(signum, &sa, &old) == 0) {
		if (old.sa_handler == SIG_IGN) {
			sigaction(signum, &old, NULL);
		}
	}
#endif
}

#ifndef _WIN32
static void catch_child(int sig_num) {
	(void) sig_num;

	/* Record that a child has exited and wake the main loop. */
	child_exited = 1;

	char data = 0;
	if (self_pipe_fds[1] >= 0 && !shutting_down) {
		ssize_t r = write(self_pipe_fds[1], &data, sizeof(data));
		if (r == -1) {
			/* Ignore transient errors (pipe full or interrupted). */
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				int saved_errno = errno;
				close(self_pipe_fds[1]);
				self_pipe_fds[1] = -1;
				errno = saved_errno;
			}
		}
	}
}
#endif

static const char *get_filename(struct my_pcap_t *my_pcap) {
	if (my_pcap->rotation_interval > 0) {
		/**
		 * When using a rotation_interval, filename templates are
		 * format strings for strftime.
		 */
		struct tm *local_tm;
		struct tm local_tm_buf;

		/* Convert rotation_start_time to a format accepted by strftime */
		if ((local_tm = localtime_r(&my_pcap->rotation_start_time, &local_tm_buf)) == NULL) {
			perror("localtime_r");
			return NULL;
		}

		char *filename = malloc(PATH_MAX);

		if (filename == NULL) {
			perror("get_filename: malloc");
			return NULL;
		}

		if (strftime((char *)filename, PATH_MAX, my_pcap->filename_template, local_tm) == 0) {
			fprintf(stderr, "get_filename: size of template expanded via strftime exceeded PATH_MAX\n");
			free(filename);
			return NULL;
		}

		return filename;
	}

	if (my_pcap->rotation_size_threshold > 0 && my_pcap->rotation_count > 0) {
		char *filename = malloc(PATH_MAX);

		if (filename == NULL) {
			perror("get_filename: malloc");
			return NULL;
		}

		if (snprintf(filename, PATH_MAX, "%s.%d", my_pcap->filename_template, my_pcap->rotation_count) >= PATH_MAX) {
			fprintf(stderr, "get_filename: size of template with count suffix exceeded PATH_MAX\n");
			free(filename);
			return NULL;
		}

		return filename;
	}

	if (!my_pcap->filename_template) {
		return NULL;
	}

	return strdup(my_pcap->filename_template);
}

static void run_postrotate_command(struct my_pcap_t *my_pcap, const char *filename) {
	if (my_pcap->verbose >= 1) {
		fprintf(stderr, "Running post-rotate command: %s\n", my_pcap->postrotate_command);
	}

	char *cmd_filename = NULL;

	if (filename != NULL) {
		cmd_filename = strdup(filename);
		if (cmd_filename == NULL) {
			perror("run_postrotate_command: strdup failed");
			return;
		}
	}

#ifdef _WIN32
	/* Windows: Use _spawnlp with _P_NOWAIT for asynchronous execution (replaces fork/exec) */
	intptr_t ret = _spawnlp(_P_NOWAIT, my_pcap->postrotate_command,
							my_pcap->postrotate_command,
							cmd_filename ? cmd_filename : "",
							NULL);
	if (ret == -1) {
		fprintf(stderr,
				"after_logrotate: _spawnlp(%s, %s) failed: %s\n",
				my_pcap->postrotate_command,
				cmd_filename ? cmd_filename : "",
				strerror(errno));
	}
	free(cmd_filename);
#else
	/* Linux: Fork/Exec */
	pid_t child;
	child = fork();
	if (child == -1) {
		perror("run_postrotate_command: fork failed");
		free(cmd_filename);
		return;
	}
	if (child == 0) {
		if (self_pipe_fds[0] >= 0) {
			close(self_pipe_fds[0]);
			self_pipe_fds[0] = -1;
		}
		if (self_pipe_fds[1] >= 0) {
			close(self_pipe_fds[1]);
			self_pipe_fds[1] = -1;
		}
	}
	if (child != 0) {
		/* Parent process. */
		free(cmd_filename);
		return;
	}

	/*
	 * Child process.
	 * Set to lowest priority so that this doesn't disturb the capture.
	 */
#ifdef NZERO
	setpriority(PRIO_PROCESS, 0, NZERO - 1);
#else
	setpriority(PRIO_PROCESS, 0, 19);
#endif
	if (execlp(my_pcap->postrotate_command,
		my_pcap->postrotate_command,
		cmd_filename ? cmd_filename : "",
		NULL) == -1) {
		fprintf(stderr,
				"after_logrotate: execlp(%s, %s) failed: %s\n",
				my_pcap->postrotate_command,
				cmd_filename ? cmd_filename : "",
				strerror(errno));
	}
	free(cmd_filename);
	_exit(127);
#endif
}

static int open_dumper(struct my_pcap_t *my_pcap, const char *filename) {
	if (my_pcap->verbose >= 1) {
		fprintf(stderr, "Opening output file: %s\n", filename);
	}

	char *filename_copy = strdup(filename ? filename : "-");
	FILE *fp = NULL;
	
	/* Identify the source handle we need to clone */
	FILE *master_handle = NULL;

	if (g_fifo_handle != NULL) {
		/* Case A: We are in Extcap mode (-F) using the global pipe */
		master_handle = g_fifo_handle;
	} else if (strcmp(filename, "-") == 0) {
		/* Case B: We are in Standalone mode (-o -) using stdout */
		master_handle = stdout;
	}

	if (master_handle != NULL) {
		/* Always duplicate the master handle.
		 * If we pass master_handle directly, pcap_dump_close() will close it,
		 * causing "Bad file descriptor" on the next rotation.
		 */
#ifdef _WIN32
		int master_fd = _fileno(master_handle);
		int new_fd = _dup(master_fd);
		if (new_fd == -1) {
			perror("open_dumper: _dup failed");
			free(filename_copy);
			return -1;
		}
		/* Force binary mode on the clone */
		_setmode(new_fd, _O_BINARY);
		fp = _fdopen(new_fd, "wb");
#else
		int master_fd = fileno(master_handle);
		int new_fd = dup(master_fd);
		if (new_fd == -1) {
			perror("open_dumper: dup failed");
			free(filename_copy);
			return -1;
		}
		fp = fdopen(new_fd, "wb");
#endif
	} else {
		/* Case C: Normal file output (-o capture.pcap) */
		fp = fopen(filename, "wb");
	}

	if (!fp) {
		fprintf(stderr, "Error opening output stream: %s\n", strerror(errno));
		free(filename_copy);
		return -1;
	}

	/* Disable buffering to prevent data getting stuck during rotation */
	setvbuf(fp, NULL, _IONBF, 0);

	pcap_dumper_t *dumper = pcap_dump_fopen(my_pcap->pcap, fp);
	if (!dumper) {
		fprintf(stderr, "Could not open pcap dumper: %s\n", pcap_geterr(my_pcap->pcap));
		/* Only close fp if it's the clone we just created */
		if (fp != master_handle) fclose(fp);
		free(filename_copy);
		return -1;
	}

	/* Cleanup old dumper if it exists */
	if (my_pcap->dumper != NULL) {
		pcap_dump_flush(my_pcap->dumper);
		pcap_dump_close(my_pcap->dumper);
	}
	if (my_pcap->filename != NULL) {
		free((void *)my_pcap->filename);
	}

	my_pcap->dumper   = dumper;
	my_pcap->filename = filename_copy;
	my_pcap->fp       = fp;

	return 0;
}

static void close_dumper(struct my_pcap_t *my_pcap) {
	if (my_pcap->dumper != NULL) {
		/* Force flush everything to the OS before closing */
		pcap_dump_flush(my_pcap->dumper);
		
		/* If we have access to the FILE*, flush it too */
		if (my_pcap->fp) {
			fflush(my_pcap->fp);
		}
		
		pcap_dump_close(my_pcap->dumper);
	}
	my_pcap->dumper   = NULL;
	if (my_pcap->filename != NULL) {
		free((void *)my_pcap->filename);
		my_pcap->filename = NULL;
	}
	my_pcap->fp       = NULL;
}

static int rotate_dumper(struct my_pcap_t *my_pcap) {
	const char *new_filename = get_filename(my_pcap);

	if (new_filename == NULL) {
		fprintf(stderr, "Could not get filename\n");
		return -1;
	}

	char *rotated_filename = NULL;
	if (my_pcap->filename != NULL) {
		rotated_filename = strdup(my_pcap->filename);
		if (rotated_filename == NULL) {
			perror("rotate_dumper: strdup failed");
			free((void *)new_filename);
			return -1;
		}
	}

	if (my_pcap->verbose) {
		fprintf(stderr, "Rotating output file: %s -> %s\n",
			rotated_filename ? rotated_filename : "<none>",
			new_filename ? new_filename : "<none>");
	}

	close_dumper(my_pcap);

	if (open_dumper(my_pcap, new_filename) != 0) {
		fprintf(stderr, "Error re-opening dumper\n");
		free((void*) new_filename);
		if (rotated_filename != NULL) {
			free(rotated_filename);
			rotated_filename = NULL;
		}
		return -1;
	}

	free((void*) new_filename);

	if (my_pcap->postrotate_command != NULL) {
		run_postrotate_command(my_pcap, rotated_filename ? rotated_filename : "");
	}

	if (rotated_filename != NULL) free(rotated_filename);

	return 0;
}

static int maybe_rotate(struct my_pcap_t *my_pcap) {

	if (my_pcap->rotation_size_threshold > 0) {
		if (my_pcap->dumper == NULL) return 0;

#ifdef HAVE_PCAP_FTELL64
		int64_t size = pcap_dump_ftell64(my_pcap->dumper);
		if (size == -1) {
			perror("pcap_dump_ftell64");
			return -1;
		}
		if (size > (int64_t)my_pcap->rotation_size_threshold) {
			++my_pcap->rotation_count;
			return rotate_dumper(my_pcap);
		}
#else
		/*
		 * XXX - this only handles a rotation_size_threshold value >
		 * 2^31-1 on LP64 platforms; to handle ILP32 (32-bit UN*X and
		 * Windows) or LLP64 (64-bit Windows) would require a version
		 * of libpcap with pcap_dump_ftell64().
		 */
		long size = (long)pcap_dump_ftell(my_pcap->dumper);
		if (size == -1) {
			perror("pcap_dump_ftell");
			return -1;
		}
		if (size > (long)my_pcap->rotation_size_threshold) {
			++my_pcap->rotation_count;
			return rotate_dumper(my_pcap);
		}
#endif
	}

	else if (my_pcap->rotation_interval > 0) {
		/* Check if it is time to rotate */
		time_t now;

		/* Get the current time */
		if ((now = time(NULL)) == (time_t) -1) {
			perror("time");
			return -1;
		}
		if (now - my_pcap->rotation_start_time >= my_pcap->rotation_interval) {
			my_pcap->rotation_start_time = now;
			return rotate_dumper(my_pcap);
		}
	}

	return 0;
}

static inline const char* name_tag(int tag,
								   const char * const names[],
								   int names_len) {
	if (tag >= 0 && tag < names_len) {
		return names[tag];
	}
	else {
		return "<UNKNOWN>";
	}
}

static void usage(const char *program) {
	fprintf(stderr,
			"\n"
			"tzsp2pcap: receive tazmen sniffer protocol over udp and\n"
			"produce pcap formatted output\n"
			"\n"
			"Usage %s [-h] [-v] [-f] [-a ADDRESS] [-p PORT] [-o FILENAME] ...\n"
			"\t-h           Display this message\n"
			"\t-v           Verbose (repeat to increase up to -vv)\n"
			"\t-f           Flush output after every packet\n"
			"\t-b FILTER    Specify a BPF capture filter (e.g., \"tcp port 80\")\n"
			"\t-a ADDRESS   Specify IP address to listen on (defaults to any)\n"
			"\t-p PORT      Specify port to listen on  (defaults to %u)\n"
			"\t-o FILENAME  Write output to FILENAME   (defaults to stdout)\n"
			"\t-s SIZE      Receive buffer size        (defaults to %u)\n"
			"\t-G SECONDS   Rotate file every n seconds\n"
			"\t-C FILESIZE  Rotate file when FILESIZE is reached\n"
			"\t-z CMD       Post-rotate command to execute\n"
			"\t-l FILEPATH  Write log messages to FILEPATH\n",
			program,
			DEFAULT_LISTEN_PORT,
			DEFAULT_RECV_BUFFER_SIZE);
}

/* Use named constants for encapsulation type mapping */
/*
 * Map TZSP encapsulation types to libpcap DLTs.
 * These values follow the MikroTik TZSP specification.
 */
static int tzsp_encap_to_dlt(uint16_t encap)
{
	switch (encap) {
		case TZSP_ENCAP_ETHERNET:
			return DLT_EN10MB;
		case TZSP_ENCAP_802_11:
			return DLT_IEEE802_11;
		case TZSP_ENCAP_802_11_PRISM:
			return DLT_PRISM_HEADER;
		case TZSP_ENCAP_802_11_AVS:
			return DLT_IEEE802_11_RADIO_AVS;
		case TZSP_ENCAP_802_11_RADIOTAP:
			return DLT_IEEE802_11_RADIO;
		/* FIX for Wave2/AX Drivers (Type 126) */
		case 126:
			return DLT_IEEE802_11_RADIO; /* Map MikroTik's 126 to standard Radiotap */
		default:
			return -1; /* unsupported */
	}
}

/* Validate log file path early */
static int validate_log_path(const char *log_path) {
	if (!log_path) {
		return 0; /* No log path specified */
	}
	
	FILE *test_fp = fopen(log_path, "a");
	if (!test_fp) {
		perror(log_path);
		return -1;
	}
	fclose(test_fp);
	return 0;
}

/* --- Extcap Helper Functions --- */
static void extcap_print_interfaces() {
	printf("extcap {version=0.0.6}{display=MikroTik TZSP Listener}{help=https://github.com/Znevna/tzsp2pcap}\n");
	printf("interface {value=tzsp}{display=TZSP Listener}{kind=nif}\n");
}

static void extcap_print_dlts() {
	/* We claim to output Ethernet, though we switch dynamically */
	printf("dlt {number=1}{name=TZSP}{display=TZSP Encapsulated}\n");
}

static void extcap_print_config() {
	printf("arg {number=0}{call=--udp-port}{display=Listen Port}{type=unsigned}{range=1,65535}{default=%d}{tooltip=UDP port to listen for TZSP packets}\n", DEFAULT_LISTEN_PORT);
	printf("arg {number=1}{call=--listen-address}{display=Listen Address}{type=string}{tooltip=IP address to bind to (leave empty for all)}\n");
	printf("arg {number=2}{call=--buffer-size}{display=Buffer Size}{type=unsigned}{default=%d}{tooltip=Receive buffer size}\n", DEFAULT_RECV_BUFFER_SIZE);
}
/* --- End Extcap Helper Functions --- */

int main(int argc, char **argv) {
	int retval = 0;
	char *capture_filter_str = NULL;
	struct bpf_program bpf_filter;
	int filter_active = 0;
	int is_extcap = 0;
	int do_capture = 0;

#ifdef _WIN32
	/* Initialize Winsock before doing anything network related */
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup failed\n");
		return 1;
	}
	/* Prevent Windows from corrupting binary output on stdout */
	if (_setmode(_fileno(stdout), _O_BINARY) == -1) {
		perror("Cannot set stdout to binary mode");
		return 1;
	}
#endif

	int         recv_buffer_size  = DEFAULT_RECV_BUFFER_SIZE;
	uint16_t    listen_port       = DEFAULT_LISTEN_PORT;
	const char *listen_addr       = NULL;
	const char *log_path          = NULL;
	char       *recv_buffer       = NULL;

	struct my_pcap_t my_pcap = {
		.pcap                    = NULL,
		.filename_template       = NULL,
		.filename                = NULL,
		.fp                      = NULL,
		.dumper                  = NULL,
		.verbose                 = 0,
		.rotation_interval       = 0,
		.rotation_start_time     = 0,
		.rotation_size_threshold = 0,
		.rotation_count          = 0,
		.postrotate_command      = NULL,
	};

	my_pcap.filename_template = strdup(DEFAULT_OUT_FILENAME);
	if (my_pcap.filename_template == NULL) {
		perror("strdup(DEFAULT_OUT_FILENAME)");
		retval = errno;
		goto exit;
	}

	char flush_every_packet = 0;

	/* Define long options for Wireshark Extcap */
	static struct option long_options[] = {
		{"extcap-interfaces", no_argument, 0, 'I'},
		{"extcap-version", optional_argument, 0, 'V'},
		{"extcap-dlts", no_argument, 0, 'D'},
		{"extcap-interface", required_argument, 0, 'i'},
		{"extcap-config", no_argument, 0, 'X'}, /* Using X to avoid conflict with -C (filesize) */
		{"extcap-capture-filter", required_argument, 0, 'U'},
		{"filter", required_argument, 0, 'b'},
		{"capture", no_argument, 0, 'Y'},
		{"fifo", required_argument, 0, 'F'},
		{"udp-port", required_argument, 0, 'P'},
		{"listen-address", required_argument, 0, 'a'},
		{"buffer-size", required_argument, 0, 'S'},
		/* Legacy short options mapped to themselves if they have no long equivalent */
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	int opt;
	int option_index = 0;

	/* Use getopt_long to parse both short (legacy) and long (extcap) arguments */
	while ((opt = getopt_long(argc, argv, ":fp:a:o:s:C:G:z:l:vhb:", long_options, &option_index)) != -1) {
		switch (opt) {
		/* --- Extcap Handling --- */
		case 'I':
			extcap_print_interfaces();
			return 0;
		case 'D':
			extcap_print_dlts();
			return 0;
		case 'X': /* --extcap-config */
			extcap_print_config();
			return 0;
		case 'V':
			printf("extcap {version=0.0.6}\n");
			return 0;
		case 'i':
			/* Wireshark passes the interface name (e.g., "tzsp"). */
			is_extcap = 1; /* Note that we are in extcap mode */
			break;
		case 'Y': /* --capture */
			do_capture = 1; /* Note that Wireshark actually wants to start */
			break;
		case 'F': /* --fifo */
		{
			/* Open the pipe ONCE and keep it in the global variable. */
			/* We never close this until the program exits. */
			g_fifo_handle = fopen(optarg, "wb");
			if (!g_fifo_handle) {
				fprintf(stderr, "Error opening pipe '%s': %s\n", optarg, strerror(errno));
				retval = -1;
				goto exit;
			}
			
			/* Disable buffering on the master handle too */
			setvbuf(g_fifo_handle, NULL, _IONBF, 0);

			/* We set filename_template to "-" just as a placeholder string,
			   but open_dumper will ignore it and use g_fifo_handle instead. */
			if (my_pcap.filename_template) free((void*)my_pcap.filename_template);
			my_pcap.filename_template = strdup("-");
			
			flush_every_packet = 1; 
			break;
		}
		case 'b': /* -b or --filter */
		case 'U': /* --extcap-capture-filter */
			if (optarg && strlen(optarg) > 0) {
				/* Free if specified multiple times to avoid memory leak */
				if (capture_filter_str) free(capture_filter_str);
				capture_filter_str = strdup(optarg);
			}
			break;
		case 'P': /* --udp-port */
			listen_port = (uint16_t)atoi(optarg);
			break;
		case 'a':
			listen_addr = optarg;
			// Basic validation check (full validation happens in setup_tzsp_listener)
			if (listen_addr && strlen(listen_addr) == 0) listen_addr = NULL;
			break;
		case 'S': /* --buffer-size */
			recv_buffer_size = atoi(optarg);
			break;

		/* --- Legacy Handling --- */
		case 'f':
			flush_every_packet = 1;
			break;

		case 'p':
		{
			char *end = NULL;
			long port_val = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0') {
				fprintf(stderr, "Invalid port '%s' provided with -p\n", optarg);
				retval = -1;
				goto exit;
			}
			if (port_val <= 0 || port_val > 65535) {
				fprintf(stderr, "Invalid port %ld (must be 1-65535)\n", port_val);
				retval = -1;
				goto exit;
			}
			listen_port = (uint16_t)port_val;
			break;
		}

		case 'o':
			if (my_pcap.filename_template) 
				free((void*)my_pcap.filename_template);
			my_pcap.filename_template = strdup(optarg);
			break;

		case 's':
		{
			char *end = NULL;
			long size_val = strtol(optarg, &end, 10);
			if (size_val <= 0 || size_val > 16 * 1024 * 1024) {
				fprintf(stderr, "Invalid receive buffer size %ld\n", size_val);
				retval = -1;
				goto exit;
			}
			recv_buffer_size = (int)size_val;
			break;
		}

		case 'v':
			my_pcap.verbose++;
			break;

		case 'G': {
			char *end = NULL;
			long rotation_interval_long = strtol(optarg, &end, 10);
			if (rotation_interval_long <= 0 || rotation_interval_long > INT_MAX) {
				fprintf(stderr, "Invalid -G seconds %ld\n",
					rotation_interval_long);
				retval = -1;
				goto exit;
			}
			my_pcap.rotation_interval = (int)rotation_interval_long;
			my_pcap.rotation_start_time = time(NULL);
			if (my_pcap.rotation_start_time == (time_t)-1) {
				perror("time");
				retval = errno;
				goto exit;
			}
			break;
		}

		case 'C': {
			char *end = NULL;
			long rotation_size_long = strtol(optarg, &end, 10);
			if (rotation_size_long <= 0 || rotation_size_long > INT_MAX) {
				fprintf(stderr, "Invalid -C filesize %ld\n",
					rotation_size_long);
				retval = -1;
				goto exit;
			}
			my_pcap.rotation_size_threshold = (int)rotation_size_long;
			break;
		}

		case 'z':
			if (my_pcap.postrotate_command)
				free((void *)my_pcap.postrotate_command);
			my_pcap.postrotate_command = strdup(optarg);
			break;

		case 'l':
			log_path = optarg;
			/* Simple whitespace check */
			const char *p = log_path;
			while (*p && isspace((unsigned char)*p)) 
				p++;
			if (*p == '\0') {
				fprintf(stderr, "Invalid -l filepath\n");
				exit(EXIT_FAILURE);
			}
			/* Validate log file early */
			if (validate_log_path(log_path) != 0) {
				fprintf(stderr, "Cannot write to log file '%s'\n", log_path);
				retval = errno;
				goto exit;
			}
			break;

		default:
		case 'h':
			usage(argv[0]);
			goto exit;
		}
	}

	/* -----------------------------------------------------------------
	 * FILTER VALIDATION: If Wireshark calls us WITHOUT --capture, 
	 * it just wants to check if the filter syntax is valid. 
	 * ----------------------------------------------------------------- */
	if (is_extcap && !do_capture) {
		if (capture_filter_str) {
			int valid = 0;
			struct bpf_program bpf;
			
			/* Check against Ethernet */
			pcap_t *dummy_eth = pcap_open_dead(DLT_EN10MB, 65535);
			if (pcap_compile(dummy_eth, &bpf, capture_filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
				valid = 1;
				pcap_freecode(&bpf);
			}
			pcap_close(dummy_eth);

			/* Check against Wi-Fi / Radiotap */
			if (!valid) {
				pcap_t *dummy_wifi = pcap_open_dead(DLT_IEEE802_11_RADIO, 65535);
				if (pcap_compile(dummy_wifi, &bpf, capture_filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
					valid = 1;
					pcap_freecode(&bpf);
				}
				pcap_close(dummy_wifi);
			}

			/* Clean up our strdup */
			free(capture_filter_str);
			
			/* Return 0 to Wireshark if valid (Green), 1 if invalid (Red) */
			return valid ? 0 : 1; 
		}
		
		/* If there's no filter and no capture flag, just exit cleanly */
		return 0;
	}
	/* ----------------------------------------------------------------- */

	if (log_path) {
		FILE *log_file = freopen(log_path, "a", stderr);
		if (!log_file) {
			perror("freopen");
			exit(EXIT_FAILURE);
		}
	}

	/**
	 * Cannot have both -C and -G provided
	 */
	if (my_pcap.rotation_size_threshold > 0 && my_pcap.rotation_interval > 0) {
		fprintf(stderr, "Cannot use both -C and -G\n");
		retval = -1;
		goto exit;
	}

#ifndef _WIN32
	/* Only setup self-pipe on Linux/Unix */
	if (pipe(self_pipe_fds) == -1) {
		perror("Creating self-wake pipe\n");
		retval = errno;
		goto exit;
	}

	/* Make both ends of the self-pipe non-blocking and set close-on-exec. */
	for (int _i = 0; _i < 2; ++_i) {
		int flags = fcntl(self_pipe_fds[_i], F_GETFL, 0);
		if (flags == -1) {
			perror("fcntl(F_GETFL) on self-pipe");
			retval = errno;
			goto err_cleanup_pipe;
		}
		if (fcntl(self_pipe_fds[_i], F_SETFL, flags | O_NONBLOCK) == -1) {
			perror("fcntl(O_NONBLOCK) on self-pipe");
			retval = errno;
			goto err_cleanup_pipe;
		}
		flags = fcntl(self_pipe_fds[_i], F_GETFD, 0);
		if (flags == -1) {
			perror("fcntl(F_GETFD) on self-pipe");
			retval = errno;
			goto err_cleanup_pipe;
		}
		if (fcntl(self_pipe_fds[_i], F_SETFD, flags | FD_CLOEXEC) == -1) {
			perror("fcntl(F_SETFD) on self-pipe");
			retval = errno;
			goto err_cleanup_pipe;
		}
	}
#endif

	/* Set up signal handlers only after the self-pipe is ready. */
	trap_signal(SIGINT);
#ifndef _WIN32
	trap_signal(SIGHUP);
#endif
	trap_signal(SIGTERM);
	
#ifndef _WIN32
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = catch_child;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGCHLD, &sa, NULL);
#endif

	int tzsp_listener = setup_tzsp_listener(listen_port, listen_addr);
	if (tzsp_listener == -1) {
		fprintf(stderr, "Could not setup tzsp listener\n");
		retval = errno;
		goto err_cleanup_pipe;
	}

	/* Allocate receive buffer BEFORE the loop */
	recv_buffer = malloc((size_t)recv_buffer_size);
	if (!recv_buffer) {
		fprintf(stderr, "Could not allocate receive buffer of %i bytes\n",
				recv_buffer_size);
		retval = -1;
		goto err_cleanup_tzsp;
	}

	/* Main loop condition checks terminate_requested explicitly */
	while (!terminate_requested) {
		fd_set read_set;

next_packet:
		if (my_pcap.verbose >= 2) {
			fprintf(stderr, ".");
		}

		FD_ZERO(&read_set);

		int maxfd = -1;

		if (tzsp_listener >= 0) {
			#ifdef _WIN32
			FD_SET((SOCKET)tzsp_listener, &read_set);
			#else
			FD_SET(tzsp_listener, &read_set);
			#endif

			if (tzsp_listener > maxfd) maxfd = tzsp_listener;
		}

#ifndef _WIN32
		if (self_pipe_fds[0] >= 0 && self_pipe_fds[0] < FD_SETSIZE) {
			FD_SET(self_pipe_fds[0], &read_set);
			if (self_pipe_fds[0] > maxfd) maxfd = self_pipe_fds[0];
		}
		
		/* Linux: Infinite timeout, wakes on pipe or packet */
		if (select(maxfd + 1, &read_set, NULL, NULL, NULL) == -1) {
			if (errno == EINTR) continue;
			perror("select");
			retval = errno;
			break;
		}
#else
		/* Windows: Select with timeout to poll for shutdown signals */
		struct timeval tv = { 0, 100000 }; /* 100ms */
		int sret = select(maxfd + 1, &read_set, NULL, NULL, &tv);
		if (sret == 0) continue; 
		if (sret == -1) {
			if (WSAGetLastError() == WSAEINTR) continue;
			fprintf(stderr, "select failed: %d\n", WSAGetLastError());
			retval = -1;
			break;
		}
#endif

#ifndef _WIN32
		if (FD_ISSET(self_pipe_fds[0], &read_set)) {
			{
				char buf[64];
				ssize_t r;
				for (;;) {
					r = read(self_pipe_fds[0], buf, sizeof(buf));
					if (r > 0) continue;
					if (r == -1) {
						if (errno == EINTR) continue;
						if (errno == EAGAIN || errno == EWOULDBLOCK) break;
						perror("read(self-pipe)");
						break;
					}
					break;
				}
			}
			if (terminate_requested) break;
			if (child_exited) {
				int saved_errno = errno;
				int status;
				pid_t pid;
				do {
					pid = waitpid(-1, &status, WNOHANG);
				} while (pid > 0);
				errno = saved_errno;
				child_exited = 0;
			}
			continue;
		}
#endif

		if (!FD_ISSET(tzsp_listener, &read_set)) {
			goto next_packet;
		}

		#ifdef _WIN32
		ssize_t readsz =
			recvfrom((SOCKET)tzsp_listener, recv_buffer, recv_buffer_size, 0,
					NULL, NULL);
		#else
		ssize_t readsz =
			recvfrom(tzsp_listener, recv_buffer, recv_buffer_size, 0,
					NULL, NULL);
		#endif

		if (readsz == -1) {
			perror("recv()");
			break;
		}
		if (readsz > recv_buffer_size) {
			fprintf(stderr, "Received oversized UDP packet\n");
			goto next_packet;
		}
		if (readsz == 0) {
			fprintf(stderr, "Zero-length UDP packet ignored\n");
			goto next_packet;
		}

		if (my_pcap.verbose >= 2) {
			fprintf(stderr, "\nread %zd bytes into buffer of size %d\n",
				readsz, recv_buffer_size);
		}

		char *p = recv_buffer;
		char *end = recv_buffer + readsz;

		if (p + sizeof(struct tzsp_header) > end) {
			fprintf(stderr, "Malformed packet (truncated header)\n");
			goto next_packet;
		}

		struct tzsp_header hdr_local;
		memcpy(&hdr_local, recv_buffer, sizeof(hdr_local));
		const struct tzsp_header *hdr = &hdr_local;

		/* Determine correct DLT from TZSP encapsulation */
		int dlt = tzsp_encap_to_dlt(ntohs(hdr->encap));
		if (dlt < 0) {
			fprintf(stderr,
				"Unsupported TZSP encapsulation type: %u (0x%04x)\n",
				(unsigned)ntohs(hdr->encap),
				(unsigned)ntohs(hdr->encap));
			goto next_packet;
		}

		/* ---------------------------------------------------------
		 * LAZY INITIALIZATION: Wait for first packet to open stream
		 * --------------------------------------------------------- */
		if (my_pcap.pcap == NULL) {
			if (my_pcap.verbose) {
				fprintf(stderr, "First packet received. Initializing stream with DLT %d\n", dlt);
			}
			my_pcap.pcap = pcap_open_dead(dlt, recv_buffer_size);
			if (!my_pcap.pcap) {
				fprintf(stderr, "Could not init pcap for DLT %d\n", dlt);
				retval = -1;
				goto err_cleanup_pcap;
			}

			const char *initial_filename = get_filename(&my_pcap);
			if (open_dumper(&my_pcap, initial_filename) == -1) {
				if (initial_filename) free((void *)initial_filename);
				retval = -1;
				goto err_cleanup_pcap;
			}
			if (initial_filename) free((void *)initial_filename);

			/* COMPILATION: Compile the capture filter for the active DLT */
			if (capture_filter_str) {
				if (pcap_compile(my_pcap.pcap, &bpf_filter, capture_filter_str, 1, PCAP_NETMASK_UNKNOWN) < 0) {
					fprintf(stderr, "Error compiling capture filter: %s\n", pcap_geterr(my_pcap.pcap));
					retval = -1;
					goto err_cleanup_pcap;
				}
				filter_active = 1;
			}
		}
		/* Fallback: If DLT changes mid-stream */
		else if (pcap_datalink(my_pcap.pcap) != dlt) {
			if (my_pcap.verbose) {
				fprintf(stderr, "DLT changed from %d to %d, rotating...\n",
						pcap_datalink(my_pcap.pcap), dlt);
			}
			
			/* Free old filter before rotating */
			if (filter_active) {
				pcap_freecode(&bpf_filter);
				filter_active = 0;
			}

			pcap_t *new_pcap = pcap_open_dead(dlt, recv_buffer_size);
			if (!new_pcap) {
				fprintf(stderr, "Could not reinitialize pcap for DLT %d\n", dlt);
				retval = -1;
				goto err_cleanup_pcap;
			}

			pcap_t *old_pcap = my_pcap.pcap;
			my_pcap.pcap = new_pcap;

			if (rotate_dumper(&my_pcap) != 0) {
				fprintf(stderr, "Error rotating dumper after DLT change\n");
				pcap_close(old_pcap);
				retval = -1;
				goto err_cleanup_pcap;
			}
			pcap_close(old_pcap);

			/* Re-compile filter for the new DLT */
			if (capture_filter_str) {
				if (pcap_compile(my_pcap.pcap, &bpf_filter, capture_filter_str, 1, PCAP_NETMASK_UNKNOWN) < 0) {
					fprintf(stderr, "Error compiling capture filter for new DLT: %s\n", pcap_geterr(my_pcap.pcap));
					retval = -1;
					goto err_cleanup_pcap;
				}
				filter_active = 1;
			}
		}

		p += sizeof(struct tzsp_header);

		if (my_pcap.verbose) {
			fprintf(stderr,
				"header { version = %u, type = %s(%u), encap = %u (0x%04x) }\n",
				(unsigned)hdr->version,
				name_tag(hdr->type,
						 tzsp_type_names, ARRAYSZ(tzsp_type_names)),
				(unsigned)hdr->type,
				(unsigned)ntohs(hdr->encap),
				(unsigned)ntohs(hdr->encap));
		}

		char got_end_tag = 0;

		if (hdr->version == 1 &&
			(hdr->type == TZSP_TYPE_RECEIVED_TAG_LIST ||
			 hdr->type == TZSP_TYPE_PACKET_FOR_TRANSMIT))
		{
			while (p < end) {
				uint8_t tag_type = (uint8_t)*p;

				if (my_pcap.verbose) {
					fprintf(stderr,
						"\ttag { type = %s(%u) }\n",
						name_tag(tag_type,
							tzsp_tag_names, ARRAYSZ(tzsp_tag_names)),
						(unsigned)tag_type);
				}

				if (tag_type == TZSP_TAG_END) {
					if (p + 1 > end) {
						fprintf(stderr, "Malformed packet (truncated END tag)\n");
						goto next_packet;
					}
					got_end_tag = 1;
					p += 1;
					break;
				}
				else if (tag_type == TZSP_TAG_PADDING) {
					p++;
				}
				else {
					if (p + 2 > end) {
						fprintf(stderr, "Malformed packet (truncated tag header)\n");
						goto next_packet;
					}

					uint8_t tag_length = (uint8_t)*(p + 1);

					if (tag_length == 0) {
						fprintf(stderr, "Malformed packet (zero-length tag)\n");
						goto next_packet;
					}

					if (p + 2 + tag_length > end) {
						fprintf(stderr, "Malformed packet (truncated tag)\n");
						goto next_packet;
					}

					p += 2 + tag_length;
				}
			}
		}
		else {
			fprintf(stderr, "Packet format not understood\n");
			goto next_packet;
		}

		if (!got_end_tag) {
			fprintf(stderr, "Packet truncated (no END tag)\n");
			goto next_packet;
		}

		ptrdiff_t payload_offset = p - recv_buffer;
		if (payload_offset < 0) {
			fprintf(stderr, "Internal error: invalid payload offset\n");
			goto next_packet;
		}

		size_t payload_off_sz = (size_t)payload_offset;
		if (payload_off_sz > (size_t)readsz) {
			fprintf(stderr, "Internal error: invalid payload offset\n");
			goto next_packet;
		}

		size_t payload_len_sz = (size_t)readsz - payload_off_sz;
		if (payload_len_sz > UINT32_MAX) {
			fprintf(stderr, "Packet too large for pcap header\n");
			goto next_packet;
		}

		if (my_pcap.dumper == NULL) {
			fprintf(stderr, "No open pcap dumper to write packet\n");
			goto next_packet;
		}

		struct pcap_pkthdr pcap_hdr = {
			.caplen = (bpf_u_int32)payload_len_sz,
			.len = (bpf_u_int32)payload_len_sz,
		};
		gettimeofday(&pcap_hdr.ts, NULL);

		/* APPLY FILTER: Drop the packet if it doesn't match */
		if (filter_active) {
			if (pcap_offline_filter(&bpf_filter, &pcap_hdr, (const u_char*) p) == 0) {
				/* Packet failed the filter criteria. Silently drop it. */
				goto next_packet;
			}
		}

		if (my_pcap.verbose) {
			fprintf(stderr,
					"\tpacket data begins at offset 0x%zx, length 0x%zx\n",
					payload_off_sz,
					payload_len_sz);
		}

		pcap_dump((u_char*) my_pcap.dumper, &pcap_hdr, (u_char*) p);

		if (my_pcap.fp && ferror(my_pcap.fp)) {
			fprintf(stderr, "error writing via pcap_dump\n");
			break;
		}

		if (flush_every_packet) {
			if (pcap_dump_flush(my_pcap.dumper) != 0) {
				fprintf(stderr, "error flushing via pcap_dump_flush\n");
				break;
			}
		}

		if (my_pcap.rotation_interval > 0 || my_pcap.rotation_size_threshold > 0) {
			if (maybe_rotate(&my_pcap) != 0) {
				retval = -1;
				goto err_cleanup_pcap;
			}
		}
	} /* End of while loop */

err_cleanup_pcap:
	if (recv_buffer) {
		free(recv_buffer);
		recv_buffer = NULL;
	}
	shutting_down = 1;

	close_dumper(&my_pcap);

	if (my_pcap.pcap) {
		pcap_close(my_pcap.pcap);
		my_pcap.pcap = NULL;
		my_pcap.fp = NULL;
	}

err_cleanup_tzsp:
	if (tzsp_listener != -1)
		cleanup_tzsp_listener(tzsp_listener);

err_cleanup_pipe:
	shutting_down = 1;
#ifndef _WIN32
	if (self_pipe_fds[0] >= 0) {
		int fd0 = self_pipe_fds[0];
		self_pipe_fds[0] = -1;
		close(fd0);
	}
	if (self_pipe_fds[1] >= 0) {
		int fd1 = self_pipe_fds[1];
		self_pipe_fds[1] = -1;
		close(fd1);
	}
#endif

exit:
	if (filter_active) {
		pcap_freecode(&bpf_filter);
	}
	if (capture_filter_str) {
		free(capture_filter_str);
	}
	if (my_pcap.filename_template)
		free((void*) my_pcap.filename_template);
	if (my_pcap.filename)
		free((void*) my_pcap.filename);
	if (my_pcap.postrotate_command)
		free((void*) my_pcap.postrotate_command);

	/* Cleanly close the Extcap pipe if it was open */
	if (g_fifo_handle) {
		fclose(g_fifo_handle);
		g_fifo_handle = NULL;
	}

#ifdef _WIN32
	WSACleanup();
#endif

	return retval;
}
