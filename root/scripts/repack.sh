./bootimg mkinitfs ramdisk | gzip -c > newrd.gz
./bootimg mkimg --kernel kernel --ramdisk newrd.gz --cmdline "console=null androidboot.hardware=qcom user_debug=23 msm_rtb.filter=0x237 ehci-hcd.park=3 androidboot.bootdevice=7824900.sdhci" --base 0x0 --pagesize 2048 --kernel_offset 0x80008000 --ramdisk_offset 0x82000000 --tags_offset 0x81e00000 --dt dtb -o boot.img 
tar cvf boot.tar boot.img
rm boot.img
