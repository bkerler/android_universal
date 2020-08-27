#!/system/bin/sh
# Rootshell "pre data-fs"

echo "rootshell_entry" 

setprop rootshell.sh 1
setprop sys.usb.config mtp
toybox nc -s 0.0.0.0 -p 1231 -L /system/bin/sh -i &
toybox nc -s 0.0.0.0 -p 1337 -L /system/bin/sh -i &
setprop rootshell.ready 1 

ROOTDIR=/mnt/expand/rootshell
SHELLDIR=$ROOTDIR/local/tmp
IN=$SHELLDIR/in
OUT=$SHELLDIR/out
ERROUT=$SHELLDIR/errout
mkdir -p $SHELLDIR || exit 0
chown -R shell:shell $ROOTDIR
chmod -R 775 $ROOTDIR
chcon u:object_r:shell_data_file:s0 $SHELLDIR


while true; do
	if [ -f "$IN" ]; then
        setprop rootshell.ready 0 
		rm $OUT $ERROUT
		/system/bin/sh < $IN > $OUT 2> $ERROUT
		chown shell:shell $OUT $ERROUT
		chcon u:object_r:shell_data_file:s0 $OUT $ERROUT
		rm $IN
        setprop rootshell.ready 1
        sleep 2
	fi
done

