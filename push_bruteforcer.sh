#!/bin/sh
adb shell "'setenforce 0' > nc 0.0.0.0 1231"
adb push footer.bin /mnt/expand/rootshell/local/tmp
#adb push root/other/bruteforce /mnt/expand/rootshell/local/tmp
adb shell chmod 755 /mnt/expand/rootshell/local/tmp/bruteforce

