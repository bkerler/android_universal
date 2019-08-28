#!/system/bin/sh
# Rootshell "pre data-fs"

while [ 1 ]
do
	if ! getprop sys.usb.config  | grep adb ; then
		setprop sys.usb.config adb
	fi
	sleep 30
done
