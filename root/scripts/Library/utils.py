import struct
import json, base64
from binascii import hexlify,unhexlify
import sys
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from .avbtool3 import *
import os
import stat

def run_command(cmd):
    '''
    proc = Popen(cmd.split(" "), stdin=PIPE, stdout=PIPE)
    if (indata!=b""):
        proc.stdin.write(indata)
    p_status=proc.wait()
    proc.stdin.close()
    return proc.stdout.read()
    '''
    #print(cmd)
    os.system(cmd)

class androidboot:
    magic="ANDROID!" #BOOT_MAGIC_SIZE 8
    kernel_size=0
    kernel_addr=0
    ramdisk_size=0
    ramdisk_addr=0
    second_addr=0
    second_size=0
    tags_addr=0
    page_size=0
    qcdt_size=0
    os_version=0
    name="" #BOOT_NAME_SIZE 16
    cmdline="" #BOOT_ARGS_SIZE 512
    id=[] #uint*8
    extra_cmdline="" #BOOT_EXTRA_ARGS_SIZE 1024

def getheader(inputfile):
    param = androidboot()
    with open(inputfile, 'rb') as rf:
        header = rf.read(0x660)
        fields = struct.unpack('<8sIIIIIIIIII16s512s8I1024s', header)
        param.magic = fields[0]
        param.kernel_size = fields[1]
        param.kernel_addr = fields[2]
        param.ramdisk_size = fields[3]
        param.ramdisk_addr = fields[4]
        param.second_size = fields[5]
        param.second_addr = fields[6]
        param.tags_addr = fields[7]
        param.page_size = fields[8]
        param.qcdt_size = fields[9]
        param.os_version = fields[10]
        param.name = fields[11]
        param.cmdline = fields[12]
        param.id = [fields[13],fields[14],fields[15],fields[16],fields[17],fields[18],fields[19],fields[20]]
        param.extra_cmdline = fields[21]
    return param

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def rotstate(state):
    if state==0:
        print("AVB-Status: VERIFIED, 0")
    else:
        print("AVB-Status: RED, 3 or ORANGE, 1")

def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

def extract_hash(pub_key,data):
    hashlen = 32 #SHA256
    encrypted = int(hexlify(data),16)
    decrypted = hex(pow(encrypted, pub_key.e, pub_key.n))[2:]
    if len(decrypted)%2!=0:
        decrypted="0"+decrypted
    decrypted=unhexlify(decrypted)
    hash = decrypted[-hashlen:]
    if (decrypted[-0x21:-0x20] != b'\x20') or (len(hash) != hashlen):
        raise Exception('Signature error')
    return hash

def get_vbmeta_pubkey(vbmetaname,partition_name):
    with open(vbmetaname, 'rb') as vbm:
        vbmeta = vbm.read()
        avbhdr = AvbVBMetaHeader(vbmeta[:AvbVBMetaHeader.SIZE])
        if avbhdr.magic != b'AVB0':
            print("Unknown vbmeta data")
            exit(0)

        class authentication_data(object):
            def __init__(self, hdr, data):
                self.hash = data[0x100 + hdr.hash_offset:0x100 + hdr.hash_offset + hdr.hash_size]
                self.signature = data[0x100 + hdr.signature_offset:0x100 + hdr.signature_offset + hdr.signature_size]

        class auxilary_data(object):
            def __init__(self, hdr, data):
                self.data = data[
                            0x100 + hdr.authentication_data_block_size:0x100 + hdr.authentication_data_block_size + hdr.auxiliary_data_block_size]

        authdata = authentication_data(avbhdr, vbmeta)
        auxdata = auxilary_data(avbhdr, vbmeta).data

        auxlen = len(auxdata)
        avbmetacontent = {}
        i = 0
        while (i < auxlen):
            desc = AvbDescriptor(auxdata[i:])
            data = auxdata[i:]
            if desc.tag == AvbPropertyDescriptor.TAG:
                avbproperty = AvbPropertyDescriptor(data)
                avbmetacontent["property"] = dict(avbproperty=avbproperty)
            elif desc.tag == AvbHashtreeDescriptor.TAG:
                avbhashtree = AvbHashtreeDescriptor(data)
                partition_name = avbhashtree.partition_name
                salt = avbhashtree.salt
                root_digest = avbhashtree.root_digest
                avbmetacontent[partition_name] = dict(salt=salt, root_digest=root_digest)
            elif desc.tag == AvbHashDescriptor.TAG:
                avbhash = AvbHashDescriptor(data)
                partition_name = avbhash.partition_name
                salt = avbhash.salt
                digest = avbhash.digest
                avbmetacontent[partition_name] = dict(salt=salt, digest=digest)
            elif desc.tag == AvbKernelCmdlineDescriptor.TAG:
                avbcmdline = AvbKernelCmdlineDescriptor(data)
                kernel_cmdline = avbcmdline.kernel_cmdline
                avbmetacontent["cmdline"] = dict(kernel_cmdline=kernel_cmdline)
            elif desc.tag == AvbChainPartitionDescriptor.TAG:
                avbchainpartition = AvbChainPartitionDescriptor(data)
                partition_name = avbchainpartition.partition_name
                public_key = avbchainpartition.public_key
                avbmetacontent[partition_name] = dict(public_key=public_key)
            i += desc.SIZE + len(desc.data)


    vbmeta_digest = None
    if partition_name in avbmetacontent:
        if "digest" in avbmetacontent[partition_name]:
            digest = avbmetacontent[partition_name]["digest"]
            vbmeta_digest = str(hexlify(digest).decode('utf-8'))
            print("VBMeta-Image-Hash: \t\t\t" + vbmeta_digest)
    else:
        return None
    pubkeydata = vbmeta[AvbVBMetaHeader.SIZE + avbhdr.authentication_data_block_size + avbhdr.public_key_offset:
                        AvbVBMetaHeader.SIZE + avbhdr.authentication_data_block_size + avbhdr.public_key_offset
                        + avbhdr.public_key_size]
    modlen = struct.unpack(">I", pubkeydata[:4])[0] // 4
    n0inv = struct.unpack(">I", pubkeydata[4:8])[0]
    modulus = hexlify(pubkeydata[8:8 + modlen]).decode('utf-8')
    return [modlen,n0inv,modulus]

def test_key(modulus):
    if modulus != "":
        modulus=modulus[:16]
        keydbname=os.path.join("root","keys","keys.json")
        datadbname=os.path.join("root", "keys", "data.json")
        if not os.path.exists(keydbname):
            print("keys.json doesn't exist. Aborting.")
            return None
        if not os.path.exists(datadbname):
            print("data.json doesn't exist. Aborting.")
            return None

        with open(keydbname,"r") as rf:
            keydb=json.loads(rf.read())
            content=""
            for key in keydb:
                if "modulus" in key:
                    info = key["modulus"][:16]
                elif "key" in key:
                    info = key["key"][:16]
                if info == modulus:
                    if "data" in key:
                        content = key["data"]
                        break
            if content!="":
                with open(datadbname, "r") as rf:
                    datadb = json.loads(rf.read())
                    for data in datadb:
                        if "id" in data:
                            if modulus==data["id"][:16]:
                                if "filename" in data:
                                    url=data["filename"]
                                    return ("Key found, "+url)
    return None

def extract_key(modulus,tmpdir):
    if modulus != "":
        modulus=modulus[:16]
        keydbname=os.path.join("root","keys","keys.json")
        datadbname=os.path.join("root", "keys", "data.json")
        if not os.path.exists(keydbname):
            print("keys.json doesn't exist. Aborting.")
            return None
        if not os.path.exists(datadbname):
            print("data.json doesn't exist. Aborting.")
            return None

        with open(keydbname,"r") as rf:
            keydb=json.loads(rf.read())
            content=""
            for key in keydb:
                if "modulus" in key:
                    info = key["modulus"][:16]
                elif "key" in key:
                    info = key["key"][:16]
                if info == modulus:
                    if "data" in key:
                        content = key["data"]
                        break
            if content!="":
                with open(datadbname, "r") as rf:
                    datadb = json.loads(rf.read())
                    for data in datadb:
                        if "id" in data:
                            if modulus==data["id"][:16]:
                                if "filename" in data:
                                    url=data["filename"]
                                    filename = url[url.rfind("/") + 1:]
                                    filename = os.path.join(tmpdir, filename)
                                    with open(filename, "wb") as wf:
                                        wf.write(base64.b64decode(content))
                                        return filename
    return None

def dump_signature(data):
    if data[0:2] == b'\x30\x82':
        slen = struct.unpack('>H', data[2:4])[0]
        total = slen + 4
        cert = struct.unpack('<%ds' % total, data[0:total])[0]

        der = DerSequence()
        der.decode(cert)
        cert0 = DerSequence()
        cert0.decode(bytes(der[1]))

        pk = DerSequence()
        pk.decode(bytes(cert0[0]))
        subjectPublicKeyInfo = pk[6]

        meta = DerSequence()
        meta.decode(der[3])
        print(der[3])
        name = meta[0][2:]
        length = meta[1]

        signature = bytes(der[4])[4:0x104]
        pub_key = RSA.importKey(subjectPublicKeyInfo)
        hash=extract_hash(pub_key,signature)
        return [name,length,hash,pub_key,bytes(der[3])[1:2]]

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
