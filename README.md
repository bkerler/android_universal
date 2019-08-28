# Android Universal Boot Rooting Toolkit 
(c) B. Kerler, MIT License

Converts stock boot images and adds hidden root (accessible via netcat session), patches selinux and adds adb. 
Tested with Android 4.x - 9.x.

## Options:
```
  -filename FILENAME, -fn FILENAME
                        boot.img or recovery.img
  -stopboot             Device will halt on boot logo
  -justunpack, -ju      Just extract kernel + ramdisk (files will be in tmp/)
  -custom, -c           Stop in order to make changes (files will be in tmp/)
  -precustom, -pc       Stop in order to make changes before patches (files will be in tmp/)
  -forcesign, -fs [1|2] Enforce signing with google keys, 1=Avbv1, 2=Avbv2
```

## Installation:

### Windows:
- You need to run makeramdisk.cmd twice. The first time being run, it will setup
  the environment.

### Linux:
```
sudo apt install python3 python3-pip
sudo pip3 install -r requirements.txt
```

## Usage:

### Linux:
```
./makeramdisk.sh -filename boot.img
```

### Windows:
```
./makeramdisk.cmd -filename boot.img
```
```
For AVBv1 : Output is boot.signed
For AVBv2 : vbmeta.img needs to be in the same directory. Output is boot.patched
```

## ToDo:
Nothing, but maybe Android 10 needs more help :)
