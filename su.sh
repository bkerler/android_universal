#!/bin/sh
adb shell "echo $@ | toybox nc 0.0.0.0 1231"
