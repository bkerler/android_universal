#!/bin/sh
adb push root/other/tcpdump /data/local/tmp/tcpdump
adb shell chmod 755 /data/local/tmp/tcpdump
adb shell "echo '/data/local/tmp/tcpdump -i 5 -s0 -w - | toybox nc -l -p 11111' | toybox nc 0.0.0.0 1231"

