./bootimg unpackimg -i boot.img -k kernel -r rd.gz -d dtb
cp boot.img boot.img.orig
rm -rf ramdisk
mkdir -p ramdisk
gunzip -c rd.gz | ./bootimg unpackinitfs -d ramdisk
