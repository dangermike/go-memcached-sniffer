# Memcached sniffer (golang edition)

Listens to memcached protocol ([documentation](https://github.com/memcached/memcached/blob/master/doc/protocol.txt)) traffic via [pcap](http://www.tcpdump.org/pcap.html). Logs protocol violations and writes the offending tcp session to a file for replay.

# Usage
* `--interface` or `-i`: The interface to sniff. Defaults to `eth0` in Linux or `en0` on a Mac.
* `--filter` or `-f`: Filter on the interface. Documentation [here](http://www.tcpdump.org/manpages/pcap-filter.7.html). Defaults to `tcp and port 11211`.
* `--snaplength` or `-s`:	Maximum size to read for each packet. Defaults to `1600`.
* `--promiscuous` or `-p`: Puts the interface into promiscuous mode.
* `--timeout` or `-t`: Timeout on a connection. Defaults to `BlockForever`. Please see the documentation on timeouts [here](https://godoc.org/github.com/google/gopacket/pcap#hdr-PCAP_Timeouts) for more information on setting this value safely.

## Requirements
### Build
This application was written in Go 1.6. Other versions of go have not been tested.

Changes to the [memcached protocol parser](memcached.rl) will not be reflected in the application unless recompiled via [Ragel](http://www.colm.net/open-source/ragel/). However, changes outside the protocol parser or simply building the application _does not_ require anything other than the basic Go toolchain and dependencies.

#### Dependencies
* [logrus](https://github.com/Sirupsen/logrus)
* [gopacket](https://github.com/google/gopacket) with [gopacket/layers](https://github.com/google/gopacket/layers) and [gopacket/pcap](https://github.com/google/gopacket/pcap)
* [minio/cli](https://github.com/minio/cli)

### Runtime
This application must be run as root to engage the pcap listener. It will not return any data otherwise.

## Acknowledgements
The Python-based [memcache-sniffer](https://github.com/forwxp/memcache-sniffer/blob/master/memcache-sniffer) project is what made the idea of this possible. Having the [Ragel State Machine Compiler](http://www.colm.net/open-source/ragel/) allowed this to be written in about a day.
