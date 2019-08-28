#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c)B.Kerler 2019

import sys
import argparse
import os
from utils import print_progress

class PatchExtract(object):
    def __init__(self):
        self._args = None

    def _parse_args(self):
        parser = argparse.ArgumentParser()

        parser.add_argument("-v", "--verbose", dest='verbose', help="verbose output",
                            action='store_true')
        parser.add_argument("-D", "--directory", dest='directory', type=str, help="set output directory", default=".")
        parser.add_argument("filename", type=str, help="vendor.new.dat or system.new.dat")

        try:
            self._args = parser.parse_args()
        except SystemExit:
            sys.exit(2)


    def run(self,filename):
        firmwarefilename=filename
        name=firmwarefilename.remove(".new.dat")
        transferfilename=name+".transfer.list"
        if not os.path.exists(transferfilename):
            print(f"Couldn't find needed {transferfilename}.")
            exit(0)
        with open(transferfilename,'r') as tfr:
            with open(firmwarefilename, 'rb') as qr:
                version=int(tfr.readline().replace("\n",""))
                if version>3:
                    print(f"Error, version {str(version)} not supported.")
                    exit(0)
                with open(name+".bin","wb") as qw:
                    totalblocks=int(tfr.readline().replace("\n",""))
                    blocksize=4096
                    buffersize=0x200000
                    ip=tfr.readline()
                    command=ip.split(" ")[0]
                    ip=ip.split(" ")[1]
                    values=ip.split(",")
                    print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    if command=="new":
                        count=int(values[0])
                        old = 0
                        for i in range(0,count/2):
                            start=int(values[1+(i*2)])
                            end=int(values[2+(i*2)])
                            length=(end-start)*blocksize
                            for pos in range(0,(blocksize*start),4096):
                                qw.write(b"\x00"*4096)
                                total=length
                            while length>0:
                                size=buffersize
                                if size>length:
                                    size=length
                                buffer=qr.read(size)
                                qw.write(buffer)
                                length-=size
                                prog = int(float(i) / float(total) * float(100))
                                if (prog > old):
                                    print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                                    old = prog
                    elif command=="erase":
                        pass

def exception_handler(exception_type, exception, traceback):
    del traceback
    sys.stderr.write("{}: {}\n".format(exception_type.__name__, exception))


if __name__ == '__main__':
    sys.excepthook = exception_handler
    pe=PatchExtract()
    pe.parse_args()
    pe.run(pe._args.filename)

