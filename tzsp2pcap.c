/*
 * tzsp2pcap for Windows
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
		if (tv) {
			FILETIME ft;
			unsigned __int64 tmpres = 0;
			GetSystemTimeAsFileTime(&ft);
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

	/* Windows select() cannot check pipes, so we rely on timeout loops instead of self-pipes */
	#define USE_SELECT_TIMEOUT 1

#else
	/* Original POSIX Includes */
	#include <sys/wait.h>
	#include <sys/param.h>
	#include <unistd.h>
	#include <sys/socket.h>
	#include <sys/select.h>
	#include <netinet/in.h>
	#include <sys/time.h>
	#include <sys/resource.h>
#endif
/* --- End Windows Compatibility Layer --- */

#include <pcap/pcap.h>

#define ARRAYSZ(x) (sizeof(x)/sizeof(*x))

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

static int setup_tzsp_listener(uint16_t listen_port) {
	int result;

	#if defined(SOCK_CLOEXEC) && !defined(_WIN32)
		int sockfd = socket(PF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	#else
		int sockfd = (int)socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	#endif
	if (sockfd == -1) {
		perror("socket()");
		goto err_exit;
	}

	#if !defined(SOCK_CLOEXEC) && !defined(_WIN32)
		int fdflags = fcntl(sockfd, F_GETFD, 0);
		if (fdflags != -1) fcntl(sockfd, F_SETFD, fdflags | FD_CLOEXEC);
	#endif

	int on = 0;
	/* Windows setsockopt expects char* for the value */
	result = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
						(char*)&on, sizeof(on));
	if (result == -1) {
		perror("setsockopt()");
		goto err_close;
	}

	struct sockaddr_in6 listen_address = {
		#if defined(SIN6_LEN) && !defined(_WIN32)
		.sin6_len = sizeof(struct sockaddr_in6),
		#endif

		.sin6_family = AF_INET6,
		.sin6_port = htons(listen_port),
		.sin6_flowinfo = 0,
		.sin6_addr = in6addr_any,
	};

	result = bind(sockfd, (struct sockaddr*) &listen_address, sizeof(listen_address));
	if (result == -1) {
		perror("bind()");
		goto err_close;
	}

	return sockfd;

err_close:
	close(sockfd);

err_exit:
	return -1;
}

static void cleanup_tzsp_listener(int socket) {
	close(socket);
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

	if (filename == NULL) {
		fprintf(stderr, "open_dumper: NULL filename\n");
		return -1;
	}

	/*
	 * Take ownership of the filename via a private copy so that
	 * my_pcap always holds heap-allocated strings that can be
	 * safely freed by rotation and at program exit.
	 */
	char *filename_copy = strdup(filename);
	if (filename_copy == NULL) {
		perror("open_dumper: strdup(filename)");
		return -1;
	}

	pcap_dumper_t *dumper = pcap_dump_open(my_pcap->pcap, filename_copy);
	if (!dumper) {
		fprintf(stderr, "Could not open output file: %s\n", pcap_geterr(my_pcap->pcap));
		free(filename_copy);
		return -1;
	}

	FILE *fp = pcap_dump_file(dumper);
	if (fp == NULL) {
		fprintf(stderr, "pcap_dump_file() returned NULL\n");
		pcap_dump_close(dumper);
		free(filename_copy);
		return -1;
	}

#ifndef _WIN32
	int dumper_fd = fileno(fp);
	if (dumper_fd != -1) {
		int fdflags = fcntl(dumper_fd, F_GETFD, 0);
		if (fdflags != -1) {
			fcntl(dumper_fd, F_SETFD, fdflags | FD_CLOEXEC);
		}
	}
#endif

	if (my_pcap->dumper != NULL) {
		pcap_dump_close(my_pcap->dumper);
	}
	if (my_pcap->filename != NULL) {
		free((void *)my_pcap->filename);
		my_pcap->filename = NULL;
	}

	my_pcap->dumper   = dumper;
	my_pcap->filename = filename_copy;
	my_pcap->fp       = fp;

	return 0;
}

static void close_dumper(struct my_pcap_t *my_pcap) {
	if (my_pcap->dumper != NULL) {
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
			perror("Can't get current_time");
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
			"Usage %s [-h] [-v] [-f] [-p PORT] [-o FILENAME] [-s SIZE] [-G SECONDS] [-C SIZE] [-z CMD] [-l FILEPATH]\n"
			"\t-h           Display this message\n"
			"\t-v           Verbose (repeat to increase up to -vv)\n"
			"\t-f           Flush output after every packet\n"
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

/*
 * Map TZSP encapsulation types to libpcap DLTs.
 * These values follow the MikroTik TZSP specification.
 */
static int tzsp_encap_to_dlt(uint16_t encap)
{
	switch (encap) {
		case 1:  /* Ethernet */
			return DLT_EN10MB;
		case 2:  /* 802.11 (no radiotap) */
			return DLT_IEEE802_11;
		case 3:  /* Prism header + 802.11 */
			return DLT_PRISM_HEADER;
		case 4:  /* AVS header + 802.11 */
			return DLT_IEEE802_11_RADIO_AVS;
		case 5:  /* Radiotap + 802.11 */
			return DLT_IEEE802_11_RADIO;
		default:
			return -1; /* unsupported */
	}
}

int main(int argc, char **argv) {
	int retval = 0;

#ifdef _WIN32
	/* Initialize Winsock before doing anything network related */
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup failed\n");
		return 1;
	}
	/* Prevent Windows from corrupting binary output on stdout */
	_setmode(_fileno(stdout), _O_BINARY); 
#endif

	int         recv_buffer_size  = DEFAULT_RECV_BUFFER_SIZE;
	uint16_t    listen_port       = DEFAULT_LISTEN_PORT;
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

	int ch;
	while ((ch = getopt(argc, argv, "fp:o:s:C:G:z:l:vh")) != -1) {
		switch (ch) {
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
				fprintf(stderr, "Invalid port %ld provided with -p (must be 1-65535)\n", port_val);
				retval = -1;
				goto exit;
			}

			listen_port = (uint16_t)port_val;
			break;
		}

		case 'o':
			if (my_pcap.filename_template) {
				free((void*) my_pcap.filename_template);
				my_pcap.filename_template = NULL;
			}
			my_pcap.filename_template = strdup(optarg);
			if (my_pcap.filename_template == NULL) {
				perror("strdup(-o filename)");
				retval = errno;
				my_pcap.filename_template = NULL;
				goto exit;
			}
			break;

		case 's':
		{
			char *end = NULL;
			long size_val = strtol(optarg, &end, 10);

			if (end == optarg || *end != '\0') {
				fprintf(stderr, "Invalid SIZE '%s' provided with -s\n", optarg);
				retval = -1;
				goto exit;
			}
			if (size_val <= 0) {
				fprintf(stderr, "Invalid receive buffer size %ld (must be > 0)\n", size_val);
				retval = -1;
				goto exit;
			}
			if (size_val > 16 * 1024 * 1024) {
				fprintf(stderr, "Receive buffer size %ld too large (max 16777216)\n", size_val);
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

			if (end == optarg || *end != '\0') {
				fprintf(stderr, "Invalid -G seconds '%s' provided\n", optarg);
				retval = -1;
				goto exit;
			}
			if (rotation_interval_long <= 0 || rotation_interval_long > INT_MAX) {
				fprintf(stderr, "Invalid -G seconds %ld provided (must be 1-%d)\n",
					rotation_interval_long, INT_MAX);
				retval = -1;
				goto exit;
			}

			int rotation_interval = (int)rotation_interval_long;

			time_t now;
			if ((now = time(NULL)) == (time_t) -1) {
				perror("Cannot get current time");
				retval = errno;
				goto exit;
			}

			my_pcap.rotation_interval   = rotation_interval;
			my_pcap.rotation_start_time = now;

			break;
		}

		case 'C': {
			char *end = NULL;
			long rotation_size_long = strtol(optarg, &end, 10);

			if (end == optarg || *end != '\0') {
				fprintf(stderr, "Invalid -C filesize '%s' provided\n", optarg);
				retval = -1;
				goto exit;
			}
			if (rotation_size_long <= 0 || rotation_size_long > INT_MAX) {
				fprintf(stderr, "Invalid -C filesize %ld provided (must be 1-%d)\n",
					rotation_size_long, INT_MAX);
				retval = -1;
				goto exit;
			}

			int rotation_size_threshold = (int)rotation_size_long;
			my_pcap.rotation_size_threshold = rotation_size_threshold;
			break;
		}

		case 'z':
			if (my_pcap.postrotate_command)
				free((void *)my_pcap.postrotate_command);
			my_pcap.postrotate_command = strdup(optarg);
			if (my_pcap.postrotate_command == NULL) {
				perror("strdup(-z cmd)");
				retval = errno;
				my_pcap.postrotate_command = NULL;
				goto exit;
			}
			break;

		case 'l': {
			log_path = optarg;

			const char *p = log_path;
			while (*p && isspace((unsigned char)*p)) {
				p++;
			}
			if (*p == '\0') {
				fprintf(stderr, "Invalid -l filepath provided for logging\n");
				exit(EXIT_FAILURE);
			}

			FILE *log_file = fopen(log_path, "a");
			if (!log_file) {
				fprintf(stderr, "Cannot open file path '%s' for writing\n", log_path);
				perror("fopen");
				exit(EXIT_FAILURE);
			}
			fclose(log_file);
			break;
		}

		default:
			retval = -1;
			/* FALLTHRU */

		case 'h':
			usage(argv[0]);
			goto exit;
		}
	}

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

	int tzsp_listener = setup_tzsp_listener(listen_port);
	if (tzsp_listener == -1) {
		fprintf(stderr, "Could not setup tzsp listener\n");
		retval = errno;
		goto err_cleanup_pipe;
	}

	{
		pcap_t *pcap = pcap_open_dead(DLT_EN10MB, recv_buffer_size);
		if (!pcap) {
			fprintf(stderr, "Could not init pcap\n");
			retval = -1;
			goto err_cleanup_tzsp;
		}
		my_pcap.pcap = pcap;
	}

	{
		const char *initial_filename = get_filename(&my_pcap);
		if (!initial_filename) {
			fprintf(stderr, "Could not get initial filename\n");
			retval = -1;
			goto err_cleanup_pcap;
		}

		if (open_dumper(&my_pcap, initial_filename) == -1) {
			free((void *)initial_filename);
			retval = -1;
			goto err_cleanup_pcap;
		}

		free((void *)initial_filename);

		if ((my_pcap.rotation_size_threshold > 0 || my_pcap.rotation_interval > 0)) {
			struct stat fp_stat;

			if (my_pcap.fp == NULL) {
				fprintf(stderr, "Output file pointer is NULL\n");
				retval = -1;
				goto err_cleanup_pcap;
			}

			if (fstat(fileno(my_pcap.fp), &fp_stat) == -1) {
				perror("fstat");
				retval = errno;
				goto err_cleanup_pcap;
			}

			if (!S_ISREG(fp_stat.st_mode)) {
				fprintf(stderr, "Output is not a regular file, but rotation was requested.\n");
				retval = -1;
				goto err_cleanup_pcap;
			}
		}
	}

	recv_buffer = malloc(recv_buffer_size);
	if (!recv_buffer) {
		fprintf(stderr, "Could not allocate receive buffer of %i bytes\n",
				recv_buffer_size);
		retval = -1;
		goto err_cleanup_pcap;
	}

	/* Main loop condition checks terminate_requested explicitly */
	while (!terminate_requested) {
		fd_set read_set;

next_packet:
		if (my_pcap.verbose >= 2) {
			fprintf(stderr, "loop_start\n");
		}

		FD_ZERO(&read_set);

		int maxfd = -1;

		if (tzsp_listener >= 0) {
			FD_SET(tzsp_listener, &read_set);
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
		if (sret == 0) continue; /* Timeout, check terminate_requested loop condition */
		if (sret == -1) {
			if (WSAGetLastError() == WSAEINTR) continue;
			fprintf(stderr, "select failed: %d\n", WSAGetLastError());
			retval = -1;
			break;
		}
#endif

#ifndef _WIN32
		if (FD_ISSET(self_pipe_fds[0], &read_set)) {
			/* Drain the self-pipe to clear wake-up notifications. */
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

			/* If a terminate request was recorded, exit the loop. */
			if (terminate_requested) {
				break;
			}

			/* If a child has exited, reap it/them here. */
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

			/* Continue to next select() without processing packets. */
			continue;
		}
#endif

		if (!FD_ISSET(tzsp_listener, &read_set)) {
			goto next_packet;
		}

		ssize_t readsz =
			recvfrom(tzsp_listener, recv_buffer, recv_buffer_size, 0,
					 NULL, NULL);

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
			fprintf(stderr,
				"read %zd bytes into buffer of size %d\n",
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
				"Unsupported TZSP encapsulation type: %u\n",
				(unsigned)ntohs(hdr->encap));
			goto next_packet;
		}

		/* If DLT changed, reopen pcap dumper */
		if (my_pcap.pcap && pcap_datalink(my_pcap.pcap) != dlt) {
			pcap_t *new_pcap = pcap_open_dead(dlt, recv_buffer_size);
			if (!new_pcap) {
				fprintf(stderr, "Could not reinitialize pcap for DLT %d\n", dlt);
				retval = -1;
				goto err_cleanup_pcap;
			}
			pcap_close(my_pcap.pcap);
			my_pcap.pcap = new_pcap;
			/* Reopen dumper with new DLT */
			if (rotate_dumper(&my_pcap) != 0) {
				fprintf(stderr, "Error rotating dumper after DLT change\n");
				retval = -1;
				goto err_cleanup_pcap;
			}
		}

		p += sizeof(struct tzsp_header);

		if (my_pcap.verbose) {
			fprintf(stderr,
					"header { version = %u, type = %s(%u), encap = 0x%.4x }\n",
					(unsigned)hdr->version,
					name_tag(hdr->type,
							 tzsp_type_names, ARRAYSZ(tzsp_type_names)),
					(unsigned)hdr->type,
					(unsigned)ntohs(hdr->encap));
		}

		char got_end_tag = 0;

		// We should only have to deal with packets of type "Received"
		// here, since we are sinking packets. However, some sniffers
		// send packets as "Transmit". While we're going to ignore the
		// intent of retransmitting the packet, there's still a valid
		// encapsulated packet here, which for the purpose of being
		// useful, we should still emit.
		if (hdr->version == 1 &&
			(hdr->type == TZSP_TYPE_RECEIVED_TAG_LIST ||
			 hdr->type == TZSP_TYPE_PACKET_FOR_TRANSMIT))
		{
			while (p < end) {
				// some packets only have the type field, which is
				// guaranteed by (p < end).

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

		if (my_pcap.verbose) {
			fprintf(stderr,
			        "\tpacket data begins at offset 0x%zx, length 0x%zx\n",
					(size_t)(p - recv_buffer),
					(size_t)(readsz - (p - recv_buffer)));
		}

		// packet remains starting at p
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

		if (my_pcap.verbose) {
			fprintf(stderr,
					"\tpacket data begins at offset 0x%zx, length 0x%zx\n",
					payload_off_sz,
					payload_len_sz);
		}

		pcap_dump((u_char*) my_pcap.dumper, &pcap_hdr, (u_char*) p);

		// since pcap_dump doesn't report errors directly, we have
		// to approximate by checking its underlying file.
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
	}

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
	if (my_pcap.filename_template)
		free((void*) my_pcap.filename_template);

	if (my_pcap.filename)
		free((void*) my_pcap.filename);

	if (my_pcap.postrotate_command)
		free((void*) my_pcap.postrotate_command);

#ifdef _WIN32
	WSACleanup();
#endif

	return retval;
}
