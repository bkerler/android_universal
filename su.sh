#!/bin/sh
adb shell "echo $1 | toybox nc 0.0.0.0 1231"
