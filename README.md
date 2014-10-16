Baskerville
======================
Reads from files or interface and writes to files in specified directory with filename based on 
unixtime of first packet in each file.  Certain protocols can be suppressed, in which case
only the first N packets are recorded to disk.  This reduces disk usage saving data which is 
of little value, such as TLS or VPNs.

Requires
*	libtrace
*	libflowmanager
*	libprotoident

These are all available to download from http://research.wand.net.nz/software/

Suggested invocation

baskerville -d pcapfile:/data/pcap -f 100M -l 10 -s HTTPS,OpenVPN ring:eth0

Dumps packets from eth0 to pcap files in /data/pcap split into 100Mb chunks.  Where HTTP and OpenVPN
sessions are detected then only the first 10 packets are saved to the pcap.

This version is BETA. Use at your own risk!

Selective protocol extractor from PCAPs or interfaces

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed for John Green, cirt at nccgroup dot com

https://github.com/nccgroup/baskerville

Released under AGPL see LICENSE for more information




