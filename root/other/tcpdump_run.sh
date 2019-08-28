#!/bin/sh
./su.sh "/data/local/tmp/tcpdump -vv -i any -s 0 -w - | toybox nc -l -p 11233"
adb forward tcp:11233 tcp:11233
nc 127.0.0.1 11233 > dump.pcap

