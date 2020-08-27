#!/usr/bin/env python3
import os
import struct
import argparse
import tarfile
import platform
import subprocess, sys
import shutil
import gzip
import stat
from Library.lz4decomp import lz4decomp
from Library.avbtool3 import *
from binascii import unhexlify,hexlify
from Library.ext4extract import Ext4Extract
from Library.simg2img import Simg2Img
from time import sleep
from Library.utils import *
import hashlib
from bootsignature import *

version="v3.28"


class androidhdr():
    def calcpadding(self, offset):
        if offset==0:
            return 0
        ft = ((offset + self.page_size - 1) // self.page_size) * self.page_size
        if offset < ft:
            return offset+int(ft - offset)
        else:
            return offset

    def __init__(self, filename):
        padding = 0
        self.image = filename
        with open(filename, "rb") as img:
            buf = img.read(48)
            padding += 48
            self.magic, self.kernel_size, self.kernel_addr, self.ramdisk_size, self.ramdisk_addr, \
            self.second_size, self.second_addr, self.tags_addr, self.page_size, self.dt_size, self.osversion \
                = struct.unpack('8sIIIIIIIIII', buf)
            buf = img.read(560)
            padding += 560
            self.name, self.cmdline, self.id0, self.id1, self.id2, self.id3, self.id4, self.id5, self.id6, self.id7 \
                = struct.unpack('16s512sIIIIIIII', buf)
            pos = self.name.index(b'\x00')
            if pos >= 0: self.name = self.name[0:pos]
            pos = self.cmdline.index(b'\x00')
            if pos >= 0: self.cmdline = self.cmdline[0:pos]
            self.startpos = 48 + 560
            if padding < self.page_size:
                img.read(self.page_size - padding)
                self.startpos += (self.page_size - padding)
            pos = self.startpos
            self.content = {}

            self.content["kernel"] = dict(foffset=pos, addr=self.kernel_addr, length=self.kernel_size)
            pos += self.calcpadding(self.kernel_size)
            self.content["ramdisk"] = dict(foffset=pos, addr=self.ramdisk_addr, length=self.ramdisk_size)
            pos += self.calcpadding(self.ramdisk_size)
            if self.second_size > 0:
                self.content["second"] = dict(foffset=pos, addr=self.second_addr, length=self.second_size)
                pos += self.calcpadding(self.second_size)
            if self.dt_size > 0:
                self.content["dt"] = dict(foffset=pos, length=self.dt_size)
                pos+=self.calcpadding(self.dt_size)

    def extract(self, type, outfilename):
        if type in self.content:
            dt = self.content[type]
            with open(self.image, 'rb') as rf:
                if "foffset" in dt:
                    rf.seek(dt["foffset"])
                if "length" in dt:
                    if dt["length"]!=0:
                        data = rf.read(dt["length"])
                        with open(outfilename, "wb") as wf:
                            wf.write(data)

    def pack(self, path, outfilename):
        pagesize = self.page_size
        hash = hashlib.sha1()

        with open(outfilename,"wb") as out:
            out.write(b'\x00'*pagesize)

            def append(filename, hash):
                file_size = 0
                if filename:
                    with open(filename, "rb") as file:
                        buf = file.read()
                        file_size = len(buf)
                        out.write(buf)
                        hash.update(buf)
                        padding = file_size % pagesize
                        if padding > 0:
                            out.write(b'\x00' * (pagesize - padding))
                hash.update(struct.pack('I', file_size))
                return file_size

            self.kernel_size=append(os.path.join(path, "kernel"),hash)
            self.ramdisk_size = append(os.path.join(path, "rd.gz"), hash)
            if os.path.exists(os.path.join(path, "second")):
                self.second_size = append(os.path.join(path, "second"), hash)
            if os.path.exists(os.path.join(path, "dtb")):
                self.dt_size = append(os.path.join(path, "dtb"), hash)
        self.id0, self.id1, self.id2, self.id3, self.id4 = struct.unpack('IIIII', hash.digest())
        with open(outfilename, "rb+") as out:
            out.write(struct.pack('8sIIIIIIIIII', b"ANDROID!", \
                                 self.kernel_size, self.kernel_addr, self.ramdisk_size, self.ramdisk_addr, \
                                 self.second_size, self.second_addr, self.tags_addr, self.page_size, \
                                 self.dt_size, self.osversion))
            out.write(struct.pack('16s512sIIIIIIII', self.name, self.cmdline, self.id0, self.id1, self.id2, \
                                 self.id3, self.id4, 0, 0, 0))
class ramdiskmod():
    custom=False
    precustom=False
    filename=""
    Linux=False
    TPATH=""
    NAME=""
    BOOTIMAGE= ""
    TARGET="boot.patched"
    disable = 0
    RPATH="tmp"
    RAMDISK = "ramdisk"
    BOOTIMG = os.path.join("root","scripts","bootimg")
    SEINJECT_TRACE_LEVEL = 1
    BB = os.path.join("root","scripts","busybox")
    BIT=64

    def __init__(self,path,filename,bit,stopboot,custom=False, precustom=False):
        self.custom=custom
        self.precustom=precustom
        self.TPATH=path
        self.stopboot=stopboot
        self.BOOTIMAGE = os.path.join(self.TPATH, filename)
        self.TARGET=os.path.join(self.TPATH,filename+".patched")
        self.RPATH=os.path.join(self.TPATH,"tmp")
        if (os.path.exists(self.RPATH)):
            shutil.rmtree(self.RPATH)
        os.mkdir(self.RPATH)

        self.RAMDISK = os.path.join(self.RPATH,"ramdisk")
        if platform.system() == "Windows":
            self.Linux=False
            self.BB +=" "
        else:
            self.Linux=True
            self.BB = ""
        self.BIT=int(bit)

    def compress(self,to_compress):
        f = open("__tmp_uncompressed__", "wb")
        f.write(to_compress)
        f.close()
        if platform.system() == "Windows":
            cmd = "root\\init-bootstrap\\quicklz.exe"
        else:
            cmd = "root/init-bootstrap/quicklz"
        if not os.path.isfile(cmd):
            raise IOError("quicklz binary not found. Please compile it first.")
        cmd = "\"" + cmd + "\"" + " comp __tmp_uncompressed__ __tmp_compressed__"
        os.system(cmd)
        f = open("__tmp_compressed__", "rb")
        data = f.read()
        f.close()
        os.remove("__tmp_uncompressed__")
        os.remove("__tmp_compressed__")
        return data


    def run(self,cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        #(output,err) = p.communicate()
        #p_status=p.wait()
        #p.stdin.write('Info\n')
        #sleep(0.1)
        output=b""
        while True:
            err = p.stderr.read(1)
            inp=b''
            if err==b'':
                inp = p.stdout.read(1)
            output+=inp
            if inp==b'' and err==b'' and p.poll() != None:
                break
            if err!=b'':
                sys.stdout.write(str(err,'utf-8'))
                sys.stdout.flush()
            if inp!=b'':
                sys.stdout.write(str(inp,'utf-8'))
                sys.stdout.flush()
        return output


    def rmrf(self,path):
        if os.path.exists(path):
            if os.path.isfile(path):
                del_rw("",path,"")
            else:
                shutil.rmtree(path, onerror=del_rw)

    def guz(self,filename):
        file_content=b""
        with gzip.open(filename,'rb') as f:
            file_content = f.read()
        return file_content

    def unpack_image(self,path):
        print("Unpacking image : %s to %s" % (self.BOOTIMAGE,path))
        self.header.extract("kernel", os.path.join(path, "kernel"))
        self.header.extract("ramdisk", os.path.join(path, "rd.gz"))
        self.header.extract("second", os.path.join(path, "second"))
        self.header.extract("dt", os.path.join(path, "dtb"))

    def unpack_initfs(self,filename,path):
        print ("- Unpacking initramfs to %s" % path)
        if os.path.exists(path):
            self.rmrf(path)
        os.mkdir(path)
        rdcpio=self.guz(os.path.join(self.RPATH,filename))
        p = subprocess.Popen(self.BOOTIMG+" unpackinitfs -d "+path,stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        p.stdin.write(rdcpio)
        sleep(0.1)
        while True:
            out = p.stderr.read(1)
            if out==b'' and p.poll() != None:
                break
            if out !=b'':
                sys.stdout.write(out)
                sys.stdout.flush()

    def pack_image(self):
        print("Packing image as %s" % self.TARGET)
        self.run(self.BOOTIMG + " mkinitfs " + self.RAMDISK + " | " + self.BB + " gzip -c > " + os.path.join(self.RPATH,"rd.gz"))
        self.header.pack(self.RPATH,self.TARGET)
        self.TARGET = self.TARGET.replace("\\", "/")
        self.rmrf(self.RPATH)

    def fix_mtp(self):
        for file in os.listdir(self.RAMDISK):
            if (len(file.split("."))>3) and "init" in file and (".usb.rc" in file or ".configfs.rc" in file):
                with open(self.RAMDISK + "/" + file, 'rb') as rf:
                    data = rf.readlines()
                with open(self.RAMDISK + "/" + file, 'wb') as wf:
                    flag = 0
                    i = 0
                    while (i < len(data)):
                        line = data[i]
                        if b"on property:sys.usb.config=mtp\n" in line or b"on property:sys.usb.config=mtp " in line:
                            while (not b"setprop sys.usb.state ${sys.usb.config}" in line):
                                line = data[i]
                                if b"setprop sys.usb.state ${sys.usb.config}" in line:
                                    wf.write(b'    start adbd\n')
                                if b"functions" in line and not b"symlink" in line:
                                    idx = line.rfind(b"functions ")
                                    line = line[:idx + 10] + b"mtp,adb\n"
                                elif b"setprop sys.usb.state" in line:
                                    break
                                wf.write(line)
                                i += 1
                        if b"on property:sys.usb.config=charging\n" in line or b"on property:sys.usb.config=charging " in line:
                            wf.write(b'on property:sys.usb.config=charging\n')
                            wf.write(b'    start adbd\n\n')
                            while (not b"setprop sys.usb.state ${sys.usb.config}" in line):
                                line = data[i]
                                if b"functions" in line:
                                    idx = line.rfind(b"functions ")
                                    line = line[:idx + 10] + b"charging,adb\n"
                                elif b"setprop sys.usb.state" in line:
                                    break
                                wf.write(line)
                                i += 1
                        if b"on property:sys.usb.ffs.mtp.ready=1 && property:sys.usb.config=mtp" in line:
                            wf.write(b'on property:sys.usb.config=mtp\n')
                            wf.write(b'    start adbd\n\n')
                            while (not b"setprop sys.usb.state ${sys.usb.config}" in line):
                                line = data[i]
                                if b"functions" in line:
                                    line2=line
                                    line2=line2.replace(b"mtp.gs0",b"ffs.adb")
                                    line2=line2.replace(b"/f1",b"/f2")
                                    wf.write(line)
                                    line=line2
                                elif b"setprop sys.usb.state" in line:
                                    break
                                wf.write(line)
                                i += 1
                        wf.write(line)
                        i += 1

    def fix_init(self):
        for file in os.listdir(self.RAMDISK):
            if "init.rc" in file:
                with open(self.RAMDISK + "/" + file, 'rb') as rf:
                    data = rf.readlines()
                with open(self.RAMDISK + "/" + file, 'wb') as wf:
                    flag = 0
                    i = 0
                    while (i < len(data)):
                        line = data[i]
                        if b"on nonencrypted" in line:
                            while (line != b"\x0A"):
                                line = data[i]
                                if (line == b"\x0A"):
                                    break
                                if (b"class_start " in line):
                                    line = b"#" + line
                                elif (b"exec_start update_verifier" in line):
                                    line = b"#" + line
                                wf.write(line)
                                i += 1
                        elif b"on property:vold.decrypt=trigger_restart_" in line:
                            while (line != b"\x0A"):
                                line = data[i]
                                if (line == b"\x0A"):
                                    break
                                if (b"class_start " in line):
                                    line = b"#" + line
                                elif (b"exec_start update_verifier" in line):
                                    line = b"#" + line
                                wf.write(line)
                                i += 1
                        wf.write(line)
                        i += 1 
                        


    def bbr(self,input):
        self.run(self.BB + input)

    def patch_stuff(self,BOOTPATH):
        print("- Doing our stuff")
        print("- Copying needed binaries")
        shutil.copyfile("root/rootshell/init.shell.rc",self.RAMDISK+"/init.shell.rc@0750")
        if not os.path.exists(self.RAMDISK + "/sbin/"):
            os.mkdir(self.RAMDISK + "/sbin")
        shutil.copyfile("root/rootshell/rootshell.sh", self.RAMDISK + "/sbin/rootshell.sh@0755")
        shutil.copyfile("root/rootshell/root_hack.sh", self.RAMDISK + "/sbin/root_hack.sh@0755")
        shutil.copyfile("root/other/bruteforce", self.RAMDISK + "/sbin/bruteforce@0755")
        shutil.copyfile("root/.android/adb_keys",self.RAMDISK+"/adb_keys")
        print("- Patching sepolicy")
        if not os.path.exists(os.path.join(self.RAMDISK,"sepolicy@0644")):
            #lz4 = lz4decomp()
            ext4 = Ext4Extract()
            simg = Simg2Img()
            if os.path.exists(os.path.join(BOOTPATH, "vendor.img")): #Android <= 9
                simg.simg2img(os.path.join(BOOTPATH, "vendor.img"), os.path.join(BOOTPATH, "vendor_converted"))
                ext4.extractext4(os.path.join(BOOTPATH, "vendor_converted"), "/etc/selinux/precompiled_sepolicy",os.path.join("tmp", "precompiled_sepolicy"))
                self.rmrf(os.path.join(BOOTPATH, "vendor_converted"))
            if os.path.exists(os.path.join(BOOTPATH, "super.img")): #Android >=10
                ext4.extractext4(os.path.join(BOOTPATH, "super.img"), "/etc/selinux/precompiled_sepolicy",os.path.join("tmp", "precompiled_sepolicy"))

            if os.path.exists(os.path.join(BOOTPATH,"tmp","precompiled_sepolicy")):
                print("- Copying precompiled_sepolicy, as sepolicy file is missing in boot !")
                shutil.copyfile(os.path.join(BOOTPATH,"tmp","precompiled_sepolicy"),os.path.join(self.RAMDISK,"sepolicy@0644"))        #$BOOTIMG magiskpolicy --load $RAMDISK/sepolicy@0644 --save $RAMDISK/sepolicy@0644 --minimal
            else:
                print("Couldn't find any valid sepolicy file. Aborting....")
                exit(0)
        self.run(self.BOOTIMG+" magiskpolicy --load "+os.path.join(self.RAMDISK,"sepolicy@0644")+" --save "+os.path.join(self.RAMDISK,"sepolicy@0644")+" --magisk")
        #$BOOTIMG magiskpolicy --load $RAMDISK/sepolicy@0644 --save $RAMDISK/sepolicy@0644 "allow su vendor_toolbox_exec file { execute_no_trans }"
        #$BOOTIMG magiskpolicy --load $RAMDISK/sepolicy@0644 --save $RAMDISK/sepolicy@0644 "allow su shell_data_file dir { search }"
        #$BOOTIMG magiskpolicy --load $RAMDISK/sepolicy@0644 --save $RAMDISK/sepolicy@0644 "allow su { port node } tcp_socket *"
        self.run(self.BOOTIMG + " magiskpolicy --load " + os.path.join(self.RAMDISK,"sepolicy@0644")+" --save " + os.path.join(self.RAMDISK,"sepolicy@0644")+" \"allow su * process { * }\"")
        self.run(self.BOOTIMG + " magiskpolicy --load " + os.path.join(self.RAMDISK,"sepolicy@0644")+" --save " + os.path.join(self.RAMDISK,"sepolicy@0644")+" \"allow * su process { * }\"")
        self.run(self.BOOTIMG + " magiskpolicy --load " + os.path.join(self.RAMDISK,"sepolicy@0644")+" --save " + os.path.join(self.RAMDISK,"sepolicy@0644")+" \"allow su vold * { * }\"")
        self.run(self.BOOTIMG + " magiskpolicy --load " + os.path.join(self.RAMDISK,"sepolicy@0644")+" --save " + os.path.join(self.RAMDISK,"sepolicy@0644")+" \"allow vold su * { * }\"")
        self.run(self.BOOTIMG + " magiskpolicy --load " + os.path.join(self.RAMDISK,"sepolicy@0644")+" --save " + os.path.join(self.RAMDISK,"sepolicy@0644")+" \"allow su system_radio_prop property_service { set }\"")
        self.run(self.BOOTIMG + " magiskpolicy --load " + os.path.join(self.RAMDISK,"sepolicy@0644")+" --save " + os.path.join(self.RAMDISK,"sepolicy@0644")+" \"allow su lock_settings_service * { * }\"")
        self.run(self.BOOTIMG + " magiskpolicy --load " + os.path.join(self.RAMDISK,"sepolicy@0644")+" --save " + os.path.join(self.RAMDISK,"sepolicy@0644")+" \"allow adbd mnt_expand_file * { * }\"")
        self.run(self.BOOTIMG + " magiskpolicy --load " + os.path.join(self.RAMDISK,"sepolicy@0644")+" --save " + os.path.join(self.RAMDISK,"sepolicy@0644")+" \"allow lock_settings_service su * { * }\"")

        #self.run(self.BOOTIMG + " magiskpolicy --load " + os.path.join(self.RAMDISK,"sepolicy@0644")+" --save " + os.#path.join(self.RAMDISK,"sepolicy@0644")+" \"allow su * process { * }\"")
        #self.run(self.BOOTIMG + " magiskpolicy --load " + os.path.join(self.RAMDISK,"sepolicy@0644")+" --save " + os.#path.join(self.RAMDISK,"sepolicy@0644")+" \"allow * su process { * }\"")

        print("- Injecting rootshell")
        self.bbr("sed -i \"/on early-init/iimport /init.shell.rc\\n\" "+os.path.join(self.RAMDISK,"init.rc@0750"))
        self.bbr("sed -i \"/trigger fs/atrigger rootshell_trigger\\n\" "+os.path.join(self.RAMDISK,"init.rc@0750"))

        print("- Injecting adb")
        ff=""
        if os.path.exists(self.RAMDISK+"/prop.default@0644"):
            ff=os.path.join(self.RAMDISK,"prop.default@0644")
        elif os.path.exists(self.RAMDISK + "/default.prop@0600"):
            ff = os.path.join(self.RAMDISK,"default.prop@0600")
        elif os.path.exists(self.RAMDISK + "/default.prop@0644"):
            ff = os.path.join(self.RAMDISK,"default.prop@0644")
        if ff!="":
            self.bbr("sed -i -e \"s/persist.sys.usb.config=.*/persist.sys.usb.config=adb/g\" "+ff)
        if os.path.exists(self.RAMDISK+"/sepolicy_version@0644"):
            print("- Injecting sepolicy_version")
            self.bbr("sed -i -e \"1 s/....$/9999/\" "+self.RAMDISK+"/sepolicy_version@0644")
        print("- Patching init")
        self.run(self.BOOTIMG+" hexpatch "+os.path.join(self.RAMDISK,"init@0750")+" 2F76656E646F722F6574632F73656C696E75782F707265636F6D70696C65645F7365706F6C69637900 2F7365706F6C6963790000000000000000000000000000000000000000000000000000000000000000")
        self.run(self.BOOTIMG+" hexpatch "+os.path.join(self.RAMDISK,"init@0750")+" 2F706C61745F7365706F6C6963792E63696C 2F706C61745F7365706F6C6963792E787878")
        self.run(self.BOOTIMG+" hexpatch "+os.path.join(self.RAMDISK,"init@0750")+" 2F646174612F73656375726974792F73706F74612F706C61745F736572766963655F636F6E7465787473 2F646174612F73656375726974792F73706F74612F706C61745F736572766963655F636F6E7465787478")
        self.run(self.BOOTIMG+" hexpatch "+os.path.join(self.RAMDISK,"init@0750")+" 2F646174612F73656375726974792F73706F74612F6E6F6E706C61745F736572766963655F636F6E7465787473 2F646174612F73656375726974792F73706F74612F6E6F6E706C61745F736572766963655F636F6E7465787478")

        self.fix_mtp()
        if self.stopboot==True:
            print("Bootimage will stop at logo !")
            self.fix_init()
        else:
            print("Bootimage will try to boot !") 
        #if (self.MODE==1):
        #    shutil.copyfile("root/magisk/init.magisk.rc",self.RAMDISK+"/init.magisk.rc@0750")
        #    if self.BIT==32:
        #        shutil.copyfile("root/magisk/magisk32",self.RAMDISK+"/sbin/magisk@0750")
        #    elif self.BIT==64:
        #        shutil.copyfile("root/magisk/magisk64", self.RAMDISK + "/sbin/magisk@0750")
        #    self.run(self.BB+"sed -i '/on early-init/iimport /init.magisk.rc\n' "+self.RAMDISK+"/init.rc@0750")


    def rotfakeavb1(self,org,target):
        fake = None
        if ".lz4" in org:
            print("Compressed lz4 boot detected, unpacking.")
            fn = os.path.join("root", "scripts", "lz4", org)
            os.system(fn)
        try:
            with open(org, "rb") as rf:
                data = rf.read()
                try:
                    param = getheader(org)
                    kernelsize = int((param.kernel_size + param.page_size - 1) / param.page_size) * param.page_size
                    ramdisksize = int((param.ramdisk_size + param.page_size - 1) / param.page_size) * param.page_size
                    secondsize = int((param.second_size + param.page_size - 1) / param.page_size) * param.page_size
                    qcdtsize = int((param.qcdt_size + param.page_size - 1) / param.page_size) * param.page_size
                    length = param.page_size + kernelsize + ramdisksize + secondsize + qcdtsize
                    fake = data[length:]
                    fake = fake[0:(int(fake[2]) << 8) + int(fake[3])+4]
                except:
                    fake = None
        except:
            print("Couldn't find " + org + ", aborting. Run makeramdisk.py -h to see help options")
            exit(1)

        target=target[:target.rfind(".")]
        if fake != None:
            if os.path.exists(target + ".signed"):
                param = getheader(target + ".signed")
                kernelsize = int((param.kernel_size + param.page_size - 1) / param.page_size) * param.page_size
                ramdisksize = int((param.ramdisk_size + param.page_size - 1) / param.page_size) * param.page_size
                secondsize = int((param.second_size + param.page_size - 1) / param.page_size) * param.page_size
                qcdtsize = int((param.qcdt_size + param.page_size - 1) / param.page_size) * param.page_size
                length = param.page_size + kernelsize + ramdisksize + secondsize + qcdtsize
                print("- Creating rot fake with length 0x%08X" % length)
                with open(target + ".signed", "rb") as rf:
                    rdata = rf.read()
                    rdata = rdata[:length]
                    with open(target + ".rotfake", "wb") as wb:
                        wb.write(rdata)
                        wb.write(fake)

    def sign(self,keyname,avbversion,outfilename):
        ssl = os.path.join('Tools', 'openssl.exe')
        config = os.path.join('Tools','openssl.cfg')
        platform = sys.platform
        if platform == "linux":
            ssl = 'openssl'
        print(f"Found key: {keyname}.")
        if avbversion==1:
            print("Signing AVBv1 using key...")
            if ".pk8" in keyname:
                name = keyname.split(".pk8")[0]
                if platform == "linux":
                    run_command(ssl + " rand -writerand ~/.rnd")
                else:
                    run_command(ssl + " rand -writerand .rnd")
                run_command(ssl + " rsa -inform DER -in " + keyname + " -outform PEM -out " + name + ".pem")
                run_command(ssl + " req -config "+config+" -new -x509 -key " + name + ".pem -out " + name + ".x509.pem -days 10000 -subj \"/C=US/ST=California/L=San Narciso/O=Yoyodyne, Inc./OU=Yoyodyne Mobility/CN=Yoyodyne/emailAddress=yoyodyne@example.com\"")
                outfilename=self.TARGET[:self.TARGET.rfind(".")]+".signed"
                if os.path.exists(outfilename):
                    os.remove(outfilename)
                shutil.copy(self.TARGET, outfilename)
                sign("/boot",outfilename, name+ ".pem",name+".x509.pem")
                verify(outfilename)
                print("Signed file written as : "+outfilename)
                #self.run("java -jar "+os.path.join("root", "scripts","BootSignature.jar")+" /boot "+self.TARGET+" "+keyname+" "+name+".x509.pem "+outfilename)
                #self.run("java -jar "+os.path.join("root", "scripts","BootSignature.jar")+" -verify "+outfilename)
        elif avbversion==2:
            print("Signing AVBv2 using key...")
            if ".pk8" in keyname:
                name = keyname.split(".pk8")[0]
                run_command(ssl + " rsa -inform DER -in "+keyname+" -outform PEM -out "+ name + ".pem")
            partition_size=os.stat(self.BOOTIMAGE).st_size
            salt=None
            self.BOOTIMAGE=self.BOOTIMAGE.replace("\\","/")
            pp=self.BOOTIMAGE[:self.BOOTIMAGE.rfind("/")+1]+"vbmeta.img"
            include_descriptors_from_image=[pp]
            output_vbmeta_image=pp
            avb=Avb()
            avb.add_hash_footer(self.TARGET,partition_size,'boot','sha256',salt,None,'SHA256_RSA4096',name+".pem",None,0,0,None,None,None,None,include_descriptors_from_image,None,None,None,None,None,output_vbmeta_image,False,False,False,False)
            if os.path.exists(pp+".signed"):
                os.remove(pp+".signed")
            os.rename(pp+".new",pp+".signed")
            if os.path.exists(self.BOOTIMAGE+".signed"):
                os.remove(self.BOOTIMAGE+".signed")
            os.rename(self.TARGET, self.BOOTIMAGE+".signed")
            '''
            python avbtool3 add_hash_footer --image boot.img --partition_size `stat --printf="%s" boot.img` --partition_name boot --key testkey_rsa4096.pem --algorithm SHA512_RSA4096 --do_not_append_vbmeta_image --output_vbmeta_image vbmeta.img
            python avbtool3 make_vbmeta_image --include_descriptors_from_image system.img --include_descriptors_from_image vendor.img --include_descriptors_from_image boot.img --include_descriptors_from_image dtbo.img --algorithm SHA256_RSA4096 --rollback_index 0 --key testkey_rsa4096.pem --output vbmeta.img
            '''

    def go(self,args,BOOTPATH,param):
        filesize=os.stat(self.BOOTIMAGE).st_size
        kernelsize = int((param.kernel_size + param.page_size - 1) / param.page_size) * param.page_size
        ramdisksize = int((param.ramdisk_size + param.page_size - 1) / param.page_size) * param.page_size
        secondsize = int((param.second_size + param.page_size - 1) / param.page_size) * param.page_size
        qcdtsize = int((param.qcdt_size + param.page_size - 1) / param.page_size) * param.page_size
        truelength = param.page_size + kernelsize + ramdisksize + secondsize + qcdtsize
        forcesign=args.forcesign
        avbversion=0
        modulus=""
        with open(self.BOOTIMAGE,'rb') as rf:
            rf.seek(truelength)
            sig = rf.read(2)
            rf.seek((filesize//0x1000*0x1000) - AvbFooter.SIZE)
            info=rf.read(4)
            if sig==b"\x30\x82":
                print("AVBv1 signature detected.")
                avbversion = 1
                rf.seek(truelength)
                signature=rf.read()
                target, siglength, hash, pub_key, flag = dump_signature(signature)
                modulus = str(hexlify(int_to_bytes(pub_key.n)).decode('utf-8'))
                exponent = str(hexlify(int_to_bytes(pub_key.e)).decode('utf-8'))
                print("\nSignature-RSA-Modulus (n):\t" + modulus)
                print("Signature-RSA-Exponent (e):\t" + exponent)
                if modulus == "e8eb784d2f4d54917a7bb33bdbe76967e4d1e43361a6f482aa62eb10338ba7660feba0a0428999b3e2b84e43c1fdb58ac67dba1514bb4750338e9d2b8a1c2b1311adc9e61b1c9d167ea87ecdce0c93173a4bf680a5cbfc575b10f7436f1cddbbccf7ca4f96ebbb9d33f7d6ed66da4370ced249eefa2cca6a4ff74f8d5ce6ea17990f3550db40cd11b319c84d5573265ae4c63a483a53ed08d9377b2bccaf50c5a10163cfa4a2ed547f6b00be53ce360d47dda2cdd29ccf702346c2370938eda62540046797d13723452b9907b2bd10ae7a1d5f8e14d4ba23534f8dd0fb1484a1c8696aa997543a40146586a76e981e4f937b40beaebaa706a684ce91a96eea49":
                    print("\n!!!! Image seems to be signed by google test keys, yay !!!!")
            elif info==b"AVBf":
                print("AVBv2 signature detected.")
                avbversion=2
                vbmetaname=os.path.join(BOOTPATH,"vbmeta.img")
                vbmetaname_a = os.path.join(BOOTPATH, "vbmeta_a.img")
                vbmetaname_b = os.path.join(BOOTPATH, "vbmeta_b.img")
                if os.path.exists(vbmetaname_a):
                    vbmetaname=vbmetaname_a
                if os.path.exists(vbmetaname_b):
                    vbmetaname=vbmetaname_b
                if os.path.exists(vbmetaname):
                    modinfo=get_vbmeta_pubkey(vbmetaname,"boot")
                    if modinfo==None:
                        print("Couldn't find \"boot\" in " + vbmetaname)
                    else:
                        modlen, n0inv, modulus=modinfo
                        print("\nSignature-RSA-Modulus (n):\t" + modulus)
                        print("Signature-n0inv: \t\t\t" + str(n0inv))
                        if modulus == "d804afe3d3846c7e0d893dc28cd31255e962c9f10f5ecc1672ab447c2c654a94b5162b00bb06ef1307534cf964b9287a1b849888d867a423f9a74bdc4a0ff73a18ae54a815feb0adac35da3bad27bcafe8d32f3734d6512b6c5a27d79606af6bb880cafa30b4b185b34daaaac316341ab8e7c7faf90977ab9793eb44aecf20bcf08011db230c4771b96dd67b604787165693b7c22a9ab04c010c30d89387f0ed6e8bbe305bf6a6afdd807c455e8f91935e44feb88207ee79cabf31736258e3cdc4bcc2111da14abffe277da1f635a35ecadc572f3ef0c95d866af8af66a7edcdb8eda15fba9b851ad509ae944e3bcfcb5cc97980f7cca64aa86ad8d33111f9f602632a1a2dd11a661b1641bdbdf74dc04ae527495f7f58e3272de5c9660e52381638fb16eb533fe6fde9a25e2559d87945ff034c26a2005a8ec251a115f97bf45c819b184735d82d05e9ad0f357415a38e8bcc27da7c5de4fa04d3050bba3ab249452f47c70d413f97804d3fc1b5bb705fa737af482212452ef50f8792e28401f9120f141524ce8999eeb9c417707015eabec66c1f62b3f42d1687fb561e45abae32e45e91ed53665ebdedade612390d83c9e86b6c2da5eec45a66ae8c97d70d6c49c7f5c492318b09ee33daa937b64918f80e6045c83391ef205710be782d8326d6ca61f92fe0bf0530525a121c00a75dcc7c2ec5958ba33bf0432e5edd00db0db33799a9cd9cb743f7354421c28271ab8daab44111ec1e8dfc1482924e836a0a6b355e5de95ccc8cde39d14a5b5f63a964e00acb0bb85a7cc30be6befe8b0f7d348e026674016cca76ac7c67082f3f1aa62c60b3ffda8db8120c007fcc50a15c64a1e25f3265c99cbed60a13873c2a45470cca4282fa8965e789b48ff71ee623a5d059377992d7ce3dfde3a10bcf6c85a065f35cc64a635f6e3a3a2a8b6ab62fbbf8b24b62bc1a912566e369ca60490bf68abe3e7653c27aa8041775f1f303621b85b2b0ef8015b6d44edf71acdb2a04d4b421ba655657e8fa84a27d130eafd79a582aa381848d09a06ac1bbd9f586acbd756109e68c3d77b2ed3020e4001d97e8bfc7001b21b116e741672eec38bce51bb4062331711c49cd764a76368da3898b4a7af487c8150f3739f66d8019ef5ca866ce1b167921dfd73130c421dd345bd21a2b3e5df7eaca058eb7cb492ea0e3f4a74819109c04a7f42874c86f63202b462426191dd12c316d5a29a206a6b241cc0a27960996ac476578685198d6d8a62da0cfece274f282e397d97ed4f80b70433db17b9780d6cbd719bc630bfd4d88fe67acb8cc50b768b35bd61e25fc5f3c8db1337cb349013f71550e51ba6126faeae5b5e8aacfcd969fd6c15f5391ad05de20e751da5b9567edf4ee426570130b70141cc9e019ca5ff51d704b6c0674ecb52e77e174a1a399a0859ef1acd87e":
                            print("\n!!!! Image seems to be signed by google test keys, yay !!!!")
        self.header = androidhdr(self.BOOTIMAGE)
        if args.cmdline != "":
            self.header.cmdline = bytes(args.cmdline,'utf-8')
            print("Command line has been patched to %s" % self.header.cmdline)
        self.unpack_image(self.RPATH)
        self.unpack_initfs("rd.gz", self.RAMDISK)
        if (self.precustom==True):
            input("- Make your changes before patches in the ramdisk (%s Folder). Press Enter to continue." % self.RAMDISK)
        if not args.nopatch==True:
            self.patch_stuff(BOOTPATH)
        if (self.custom==True):
            input("- Make your changes after patches in the ramdisk (%s Folder). Press Enter to continue." % self.RAMDISK)
        self.pack_image()
        KEYPATH = "key"
        if (os.path.exists(KEYPATH)):
            shutil.rmtree(KEYPATH)
        os.mkdir(KEYPATH)
        if os.path.exists("key"):
            keyname = extract_key(modulus, KEYPATH)
            if keyname != None:
                self.sign(keyname,avbversion,self.TARGET + ".signed")
            else:
                if avbversion==1 or forcesign==1:
                    print(f"Creating rotfake...")
                    if forcesign==1:
                        avbversion=1
                        modulus="e8eb784d2f4d54917a7bb33bdbe76967e4d1e43361a6f482aa62eb10338ba7660feba0a0428999b3e2b84e43c1fdb58ac67dba1514bb4750338e9d2b8a1c2b1311adc9e61b1c9d167ea87ecdce0c93173a4bf680a5cbfc575b10f7436f1cddbbccf7ca4f96ebbb9d33f7d6ed66da4370ced249eefa2cca6a4ff74f8d5ce6ea17990f3550db40cd11b319c84d5573265ae4c63a483a53ed08d9377b2bccaf50c5a10163cfa4a2ed547f6b00be53ce360d47dda2cdd29ccf702346c2370938eda62540046797d13723452b9907b2bd10ae7a1d5f8e14d4ba23534f8dd0fb1484a1c8696aa997543a40146586a76e981e4f937b40beaebaa706a684ce91a96eea49"
                    keyname = extract_key(modulus, KEYPATH)
                    if keyname is None:
                        avbversion = 1
                        modulus="e8eb784d2f4d54917a7bb33bdbe76967e4d1e43361a6f482aa62eb10338ba7660feba0a0428999b3e2b84e43c1fdb58ac67dba1514bb4750338e9d2b8a1c2b1311adc9e61b1c9d167ea87ecdce0c93173a4bf680a5cbfc575b10f7436f1cddbbccf7ca4f96ebbb9d33f7d6ed66da4370ced249eefa2cca6a4ff74f8d5ce6ea17990f3550db40cd11b319c84d5573265ae4c63a483a53ed08d9377b2bccaf50c5a10163cfa4a2ed547f6b00be53ce360d47dda2cdd29ccf702346c2370938eda62540046797d13723452b9907b2bd10ae7a1d5f8e14d4ba23534f8dd0fb1484a1c8696aa997543a40146586a76e981e4f937b40beaebaa706a684ce91a96eea49"
                        keyname = extract_key(modulus, KEYPATH)
                    if keyname is not None:
                        self.sign(keyname, avbversion, self.TARGET + ".signed")
                    self.rotfakeavb1(self.BOOTIMAGE, self.TARGET)

                    
                elif avbversion==2 or forcesign==2:
                    if forcesign==2:
                        avbversion=2
                        modulus="d804afe3d3846c7e0d893dc28cd31255e962c9f10f5ecc1672ab447c2c654a94b5162b00bb06ef1307534cf964b9287a1b849888d867a423f9a74bdc4a0ff73a18ae54a815feb0adac35da3bad27bcafe8d32f3734d6512b6c5a27d79606af6bb880cafa30b4b185b34daaaac316341ab8e7c7faf90977ab9793eb44aecf20bcf08011db230c4771b96dd67b604787165693b7c22a9ab04c010c30d89387f0ed6e8bbe305bf6a6afdd807c455e8f91935e44feb88207ee79cabf31736258e3cdc4bcc2111da14abffe277da1f635a35ecadc572f3ef0c95d866af8af66a7edcdb8eda15fba9b851ad509ae944e3bcfcb5cc97980f7cca64aa86ad8d33111f9f602632a1a2dd11a661b1641bdbdf74dc04ae527495f7f58e3272de5c9660e52381638fb16eb533fe6fde9a25e2559d87945ff034c26a2005a8ec251a115f97bf45c819b184735d82d05e9ad0f357415a38e8bcc27da7c5de4fa04d3050bba3ab249452f47c70d413f97804d3fc1b5bb705fa737af482212452ef50f8792e28401f9120f141524ce8999eeb9c417707015eabec66c1f62b3f42d1687fb561e45abae32e45e91ed53665ebdedade612390d83c9e86b6c2da5eec45a66ae8c97d70d6c49c7f5c492318b09ee33daa937b64918f80e6045c83391ef205710be782d8326d6ca61f92fe0bf0530525a121c00a75dcc7c2ec5958ba33bf0432e5edd00db0db33799a9cd9cb743f7354421c28271ab8daab44111ec1e8dfc1482924e836a0a6b355e5de95ccc8cde39d14a5b5f63a964e00acb0bb85a7cc30be6befe8b0f7d348e026674016cca76ac7c67082f3f1aa62c60b3ffda8db8120c007fcc50a15c64a1e25f3265c99cbed60a13873c2a45470cca4282fa8965e789b48ff71ee623a5d059377992d7ce3dfde3a10bcf6c85a065f35cc64a635f6e3a3a2a8b6ab62fbbf8b24b62bc1a912566e369ca60490bf68abe3e7653c27aa8041775f1f303621b85b2b0ef8015b6d44edf71acdb2a04d4b421ba655657e8fa84a27d130eafd79a582aa381848d09a06ac1bbd9f586acbd756109e68c3d77b2ed3020e4001d97e8bfc7001b21b116e741672eec38bce51bb4062331711c49cd764a76368da3898b4a7af487c8150f3739f66d8019ef5ca866ce1b167921dfd73130c421dd345bd21a2b3e5df7eaca058eb7cb492ea0e3f4a74819109c04a7f42874c86f63202b462426191dd12c316d5a29a206a6b241cc0a27960996ac476578685198d6d8a62da0cfece274f282e397d97ed4f80b70433db17b9780d6cbd719bc630bfd4d88fe67acb8cc50b768b35bd61e25fc5f3c8db1337cb349013f71550e51ba6126faeae5b5e8aacfcd969fd6c15f5391ad05de20e751da5b9567edf4ee426570130b70141cc9e019ca5ff51d704b6c0674ecb52e77e174a1a399a0859ef1acd87e"
                    keyname = extract_key(modulus, KEYPATH)
                    self.sign(keyname,avbversion,self.TARGET + ".signed")
                else:
                        print("Image wasn't signed as we do not have the right key. Force signing with google keys using -forcesign.")
            print("Done :D")
        return

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,description='Makeramdisk '+version+' (c) B. Kerler 2019')

    parser.add_argument(
        '-stopboot', '-s',
        help='Stop at boot logo',
        action="store_true",
        default=False) 

    parser.add_argument(
        '-filename', '-fn',
        help='boot.img or recovery.img',
        default="boot.img")

    parser.add_argument(
        '-justunpack', '-ju',
        help='Just extract kernel + ramdisk',
        action="store_true",
        default=False)

    parser.add_argument(
        '-nopatch', '-np',
        help='Do not add root patch',
        action="store_true",
        default=False)

    parser.add_argument(
        '-custom', '-c',
        help='Stop in order to make changes',
        action="store_true",
        default=False)

    parser.add_argument(
        '-precustom', '-pc',
        help='Stop in order to make changes before patches',
        action="store_true",
        default=False)

    parser.add_argument(
        '-forcesign', '-fs',
        help='Force google sign [1=AVBv1, 2=AVBv2]',
        type=int,
        default=0)

    parser.add_argument(
        '-cmdline', '-cmd',
        help='Modify command line',
        default="")

    args = parser.parse_args()
    
    stopboot=args.stopboot 
    custom=args.custom
    precustom=args.precustom

    print("\nMakeramdisk Android "+version+" (c) B. Kerler 2019")
    print("---------------------------------------------\n")
    
    BOOTPATH,BOOTIMAGE=path,filename=os.path.split(args.filename)


    try:
        with open(os.path.join(BOOTPATH,BOOTIMAGE),"rb") as rf:
             data=rf.read()
    except Exception as e:
        print(e)
        print("Couldn't find boot.img, aborting. Use -h for help or -fn [boot.img].")
        #print(BOOTPATH)
        #print(BOOTIMAGE)
        #print(TMPPATH)
        exit(1)
    
    #scriptpath=os.path.join("root","scripts","patchit.sh")
    
    busybox=os.path.join("root","scripts","busybox")+" ash "
    Linux=False
    if platform.system()=="Windows":
        print("Windows detected.")
    else:
        print("Linux/Mac detected.")
        busybox=""
        Linux=True

    idx=data.find(b"aarch64")
    bit=32
    if (idx!=-1):
        print("64Bit detected")
        bit=64
    else:
        print("32Bit detected")
        bit=32

    filename=""
    if os.path.exists(args.filename):
        BOOTPATH,BOOTIMAGE=os.path.split(args.filename)
    
    rdm = ramdiskmod(BOOTPATH,BOOTIMAGE,int(bit),stopboot,custom,precustom)
    param = getheader(args.filename)
    if args.justunpack==True:
        rdm.RPATH=os.path.join(BOOTPATH,rdm.RPATH)
        rdm.RAMDISK=os.path.join(BOOTPATH,rdm.RAMDISK)
        rdm.header = androidhdr(args.filename)
        rdm.unpack_image(rdm.RPATH)
        if os.path.exists(os.path.join(rdm.RPATH,'rd.gz')):
            rdm.unpack_initfs("rd.gz", rdm.RAMDISK)
        print("Done !")
    else:
        rdm.go(args,BOOTPATH,param)

if __name__ == '__main__':
    main()
