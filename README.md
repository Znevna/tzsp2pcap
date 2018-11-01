# tzsp2pcap

## Introduction
This is a simple utility to listen for [TaZmen Sniffer Protocol](http://en.wikipedia.org/wiki/TZSP)
packets and output the contents on stdout in PCAP format. It has only
been lightly tested with Mikrotik RouterOS products, and may need
alterations to work with other devices.

## Usage
```
Usage tzsp2pcap [-h] [-v] [-f] [-p PORT] [-o FILENAME] [-s SIZE] [-G SECONDS] [-C SIZE] [-z CMD]
    -h           Display this message
    -v           Verbose (repeat to increase up to -vv)
    -f           Flush output after every packet
    -p PORT      Specify port to listen on  (defaults to 37008)
    -o FILENAME  Write output to FILENAME   (defaults to stdout)
    -s SIZE      Receive buffer size        (defaults to 65535)
    -G SECONDS   Rotate file every n seconds
    -C FILESIZE  Rotate file when FILESIZE is reached
    -z CMD       Post-rotate command to execute
```

## Example usage
Pipe live packet capture into [Wireshark](https://www.wireshark.org/):
```
tzsp2pcap -f | wireshark -k -i -
```
Pipe live packet capture into [tcpreplay](http://tcpreplay.synfin.net/):
```
/tzsp2pcap -f | tcpreplay --topspeed -i dummy0 -
```
Rotate file every 1MB (file.pcap.1, file.pcap.2, etc):
```
tzsp2pcap -o "file.pcap" -C 1000000 
```
Create new file every 10 seconds (file_UNIXTIMESTAMP.pcap):
```
tzsp2pcap -o "file_%s.pcap" -G 10
```
Rotate file every 1MB and compress it (file.pcap.1.gz, file.pcap.2.gz, etc):
```
tzsp2pcap -o "file.pcap" -C 1000000 -z gzip
```
