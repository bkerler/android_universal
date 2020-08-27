#! /usr/bin/env python3
# Super Extractor (c) B.Kerler 2019, MIT License

import os
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
              data = fill_bin * (chunk_sz * blk_sz // 4)
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


def read_object(data, definition):
    '''
    Unpacks a structure using the given data and definition.
    '''
    obj = {}
    object_size = 0
    pos=0
    for (name, stype) in definition:
        object_size += struct.calcsize(stype)
        obj[name] = struct.unpack(stype, data[pos:pos+struct.calcsize(stype)])[0]
        pos+=struct.calcsize(stype)
    obj['object_size'] = object_size
    obj['raw_data'] = data
    return obj

# Print iterations progress
def print_progress(iteration, total, prefix='', suffix='', decimals=1, bar_length=100):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        bar_length  - Optional  : character length of bar (Int)
    """
    str_format = "{0:." + str(decimals) + "f}"
    percents = str_format.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    bar = '█' * filled_length + '-' * (bar_length - filled_length)

    sys.stdout.write('\r%s |%s| %s%s %s' % (prefix, bar, percents, '%', suffix)),

    if iteration == total:
        sys.stdout.write('\n')
    sys.stdout.flush()

class superfs(object):
  def __init__(self):
      self.LpMetadataGeometry = [
          ('magic', '<I'),
          ('struct_size', '<I'),
          ('crc32', '32s'),
          ('metadata_max_size', '<I'),
          ('metadata_slot_count', '<I'),
          ('logical_block_size', '<I')
      ]

      self.LpMetadataHeader = [
          ('magic', '<I'),
          ('major_version', '<H'),
          ('minor_version', '<H'),
          ('header_size', '<I'),
          ('header_checksum', '32s'),
          ('tables_size', '<I'),
          ('tables_checksum', '32s')
      ]

      self.LpMetadataTableDescriptor = [
          ('offset', '<I'),
          ('num_entries', '<I'),
          ('entry_size', '<I')
      ]

      self.LpMetadataPartition = [
          ('name', '36s'),
          ('attributes', '<I'),
          ('first_extent_index', '<I'),
          ('num_extents', '<I'),
          ('group_index', '<I')
      ]

      self.LpMetadataExtent = [
          ('num_sectors', '<Q'),
          ('target_type', '<I'),
          ('target_data', '<Q'),
          ('target_source', '<I')
      ]

      self.LpMetadataPartitionGroup = [
          ('name', '36s'),
          ('flags', '<I'),
          ('maximum_size', '<Q')
      ]

      self.LpMetadataBlockDevice = [
          ('first_logical_sector', '<Q'),
          ('alignment', '<I'),
          ('alignment_offset', '<I'),
          ('size', '<Q'),
          ('partition_name', '36s'),
          ('flags', '<I'),
      ]

      self.pblocksize=512


  def extract(self,infilename, outdir):
    if infilename != "":
      with open(infilename, "rb") as rf:
        ''' Geometry '''
        rf.seek(0)
        hdr=struct.unpack("<I",rf.read(4))[0]
        nf=""
        if hdr==0xED26FF3A:
            print("Sparse format detected, unpacking super.dat")
            sp=os.path.dirname(infilename)
            nf=os.path.join(sp,"super.dat")
            Simg2Img().simg2img(infilename, nf)
            infilename=nf
      with open(infilename,'rb') as rf:
        rf.seek(0x1000)
        tmp=rf.read(4+4+32+4+4+4)
        geometry=read_object(tmp,self.LpMetadataGeometry)
        if geometry["magic"]!=0x616C4467:
            print("No or unknown super geometry !")
            exit(0)
        blocksize=geometry["logical_block_size"]
        metadata_slot_count = geometry["metadata_slot_count"]

        ''' Backup of Geometry '''
        rf.seek(blocksize*2)
        tmp = rf.read(4 + 4 + 32 + 4 + 4 + 4)
        backupgeometry = read_object(tmp, self.LpMetadataGeometry)


        ''' Header '''
        hdrstart=blocksize * 3
        rf.seek(hdrstart)
        tmp = rf.read(4 + 2 + 2 + 4 + 32 + 4 + 32)
        header = read_object(tmp, self.LpMetadataHeader)
        if header["magic"]!=0x414C5030:
            print("Unknown Header magic")
            exit(0)
        header_size=header["header_size"]
        tmp = rf.read(4+4+4)
        metapartitions=read_object(tmp,self.LpMetadataTableDescriptor)
        tmp = rf.read(4+4+4)
        metaextents=read_object(tmp,self.LpMetadataTableDescriptor)
        tmp = rf.read(4 + 4 + 4)
        metagroups = read_object(tmp, self.LpMetadataTableDescriptor)
        tmp = rf.read(4 + 4 + 4)
        metadevices = read_object(tmp, self.LpMetadataTableDescriptor)

        ''' Partitions '''
        partstart=(blocksize*3)+header_size
        rf.seek(partstart)
        partitions=[]
        parted={}
        for pos in range(0,metapartitions["num_entries"]):
            tmp=rf.read(metapartitions["entry_size"])
            prt=read_object(tmp[:36+4+4+4+4],self.LpMetadataPartition)
            if prt["num_extents"]>0:
                parted[prt["first_extent_index"]]=prt["name"].replace(b"\x00",b"").decode('utf-8')
            partitions.append(prt)

        ''' Extents '''
        extentstart=partstart + (metapartitions["num_entries"] * metapartitions["entry_size"])
        rf.seek(extentstart)
        extents=[]
        for pos in range(0,metaextents["num_entries"]):
            tmp=rf.read(metaextents["entry_size"])
            ext=read_object(tmp[:8+4+8+4],self.LpMetadataExtent)
            extents.append(ext)

        ''' PartitionGroup '''
        prtgroupstart=extentstart + (metaextents["num_entries"] * metaextents["entry_size"])
        rf.seek(prtgroupstart)
        partgroups=[]
        for pos in range(0,metapartitions["num_entries"]):
            tmp=rf.read(metapartitions["entry_size"])
            pg=read_object(tmp[:36+4+8],self.LpMetadataPartitionGroup)
            partgroups.append(pg)

        ''' BlockDevice '''
        blockdevstart=prtgroupstart + (metapartitions["num_entries"] * metapartitions["entry_size"])
        rf.seek(blockdevstart)
        blockdevices=[]
        for pos in range(0,metadevices["num_entries"]):
            tmp=rf.read(metadevices["entry_size"])
            pg=read_object(tmp[:8+4+4+8+36+4],self.LpMetadataBlockDevice)
            blockdevices.append(pg)

        for blockdevice in blockdevices:
            blockstart=blockdevice["first_logical_sector"]*self.pblocksize

        for i in range(0,len(extents)):
            name=f"unknown{i}.bin"
            if i in parted:
                name=parted[i]+".bin"
            extent=extents[i]
            offset=extent["target_data"]*self.pblocksize
            length=extent["num_sectors"]*self.pblocksize
            rf.seek(offset)
            filename=os.path.join(outdir,name)
            written=0
            total=length
            old=0
            print("Writing "+filename)
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            with open(filename,"wb") as wf:
                while length>0:
                    size=0x200000
                    if length<size:
                        size=length
                    data=rf.read(size)
                    written+=size
                    wf.write(data)
                    length-=size
                    prog=int(written/total*100.0)
                    if prog>old:
                        print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                        old=prog
    if nf!="":
        os.remove(nf)

def main():
    if len(sys.argv)<3:
        print("Usage: superextract.py [infilename] [directory_to_extract]")
        exit(0)
    infilename=sys.argv[1]
    outdir=sys.argv[2]
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    superfs().extract(infilename, outdir)
    print("Done")
    sys.exit(0)

if __name__ == "__main__":
  main()