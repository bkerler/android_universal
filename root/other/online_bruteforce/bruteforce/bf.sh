#mount /system
#rm -rf /vendor
#ln -s /system/vendor /vendor
#qseecomd&
cd /data/local/tmp
echo 1 > /sys/class/power_supply/battery/charging_enabled
/sbin/charger &
/sbin/bruteforce hw < wordlist.txt

BLKDEV=/dev/block/bootdevice/by-name/userdata
BLKDEVSSD=/dev/block/bootdevice/by-name/ssd
BLKDEV_SIZE=$(blockdev --getsize64 $BLKDEV)
OFFSET=$(expr $BLKDEV_SIZE - 16384)
OFFSET=$(expr $OFFSET / 512)
dd if=/data/local/tmp/footer.bin count=32 skip=$OFFSET bs=512 of=$BLKDEV
dd if=/data/local/tmp/ssd of=$BLKDEVSSD 
sync

