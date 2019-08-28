#!/system/bin/sh
BLKDEV=/dev/block/bootdevice/by-name/userdata
BLKDEVSSD=/dev/block/bootdevice/by-name/ssd
BLKDEV_SIZE=$(blockdev --getsize64 $BLKDEV)
OFFSET=$(expr $BLKDEV_SIZE - 16384)
OFFSET=$(expr $OFFSET / 512)
dd if=$BLKDEV count=32 skip=$OFFSET bs=512 of=/data/local/tmp/footer.bin
dd if=$BLKDEVSSD of=/data/local/tmp/ssd
chmod 755 /data/local/tmp/footer.bin
chmod 755 /data/local/tmp/ssd
