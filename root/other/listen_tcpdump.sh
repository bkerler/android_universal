#!/bin/sh
adb forward tcp:11111 tcp:11111
nc localhost 11111 | wireshark -k -S -i -

