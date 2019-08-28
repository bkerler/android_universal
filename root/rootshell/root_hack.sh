#!/system/bin/sh

# get writable ramdisk
mount -o rw,remount /
# move everything prepared from /data/local/tmp
chmod 0750 /data/local/tmp/*
cp /data/local/tmp/* /sbin

# create symlink from /data/local/tmp -> /sbin, so frida_server will be happy
rm -rf /data/local/tmp
ln -s /sbin/ /data/local/tmp

/sbin/frida_server -D

# new tmp dir for uploading/downloading files
mkdir /data/local/disk
chown shell:shell /data/local/disk
chcon -h u:object_r:shell_data_file:s0 /data/local/disk
