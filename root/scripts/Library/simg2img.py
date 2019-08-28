#! /usr/bin/env python3

# Copyright (C) 2012 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function
import posixpath
import struct
import sys

class Simg2Img(object):
  def simg2img(self,infilename, outfilename):
    if infilename != "":
      FH = open(infilename, "rb")
      header_bin = FH.read(28)
      header = struct.unpack("<I4H4I", header_bin)
      me="simg2img"
      magic = header[0]
      major_version = header[1]
      minor_version = header[2]
      file_hdr_sz = header[3]
      chunk_hdr_sz = header[4]
      blk_sz = header[5]
      total_blks = header[6]
      total_chunks = header[7]
      image_checksum = header[8]

      if magic != 0xED26FF3A:
        print("%s: %s: Magic should be 0xED26FF3A but is 0x%08X"
              % (me, infilename, magic))
      if major_version != 1 or minor_version != 0:
        print("%s: %s: I only know about version 1.0, but this is version %u.%u"
              % (me, infilename, major_version, minor_version))
      if file_hdr_sz != 28:
        print("%s: %s: The file header size was expected to be 28, but is %u."
              % (me, infilename, file_hdr_sz))
      if chunk_hdr_sz != 12:
        print("%s: %s: The chunk header size was expected to be 12, but is %u."
              % (me, infilename, chunk_hdr_sz))

      print("%s: Total of %u %u-byte output blocks in %u input chunks."
            % (infilename, total_blks, blk_sz, total_chunks))

      if image_checksum != 0:
        print("checksum=0x%08X" % (image_checksum))

      offset = 0
      FH.seek(0x1C)
      with open(outfilename, "wb") as wf:
        for i in range(1, total_chunks + 1):
          header_bin = FH.read(12)
          header = struct.unpack("<2H2I", header_bin)
          chunk_type = header[0]
          chunk_sz = header[2]
          total_sz = header[3]
          data_sz = total_sz - 12
          curhash = ""
          curtype = ""
          curpos = FH.tell()

          if chunk_type == 0xCAC1:
            if data_sz != (chunk_sz * blk_sz):
              print("Raw chunk input size (%u) does not match output size (%u)"
                    % (data_sz, chunk_sz * blk_sz))
              break
            else:
              curtype = "Raw data"
              data = FH.read(chunk_sz * blk_sz)
              wf.write(data)
          elif chunk_type == 0xCAC2:
            if data_sz != 4:
              print("Fill chunk should have 4 bytes of fill, but this has %u"
                    % (data_sz))
              break
            else:
              fill_bin = FH.read(4)
              fill = struct.unpack("<I", fill_bin)
              curtype = format("Fill with 0x%08X" % (fill))
              data = fill_bin * (blk_sz / 4);
              wf.write(data)
          elif chunk_type == 0xCAC3:
            wf.write(b'\x00' * chunk_sz * blk_sz)
          elif chunk_type == 0xCAC4:
            if data_sz != 4:
              print("CRC32 chunk should have 4 bytes of CRC, but this has %u"
                    % (data_sz))
              break
            else:
              crc_bin = FH.read(4)
              crc = struct.unpack("<I", crc_bin)
              curtype = format("Unverified CRC32 0x%08X" % (crc))
          else:
            print("Unknown chunk type 0x%04X" % (chunk_type))
            break
          offset += chunk_sz

        if total_blks != offset:
          print("The header said we should have %u output blocks, but we saw %u"
                % (total_blks, offset))

'''
def main():
  me = posixpath.basename(sys.argv[0])
  if len(sys.argv)<3:
      print("Usage: simg2img.py [infilename] [outfilename]")
      exit(0)
  infilename=sys.argv[1]
  outfilename=sys.argv[2]

  Simg2Img().simg2img(infilename, outfilename)

  sys.exit(0)

if __name__ == "__main__":
  main()
'''