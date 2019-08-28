#!/bin/sh
adb forward tcp:1231 tcp:1231
echo "Enter your commands below (root)":
nc localhost 1231


