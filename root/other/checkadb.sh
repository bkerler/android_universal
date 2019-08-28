while [ 1 ]
do
	if ! getprop sys.usb.config | grep adb; then                 
		echo "enable adb..."	
		resetprop sys.usb.config adb	
 	fi
	sleep 30
done
