import struct
import json, base64
from binascii import hexlify,unhexlify
import sys
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from .avbtool3 import *
import os
import stat

#!/usr/bin/python3
# -*- coding: utf-8 -*-
#(c) B.Kerler 2018-2019, ZITiS, Do not distribute without permission !

import hashlib
from binascii import hexlify,unhexlify

class rsa:  # RFC8017
        def __init__(self, hashtype="SHA256"):
            if hashtype == "SHA1":
                self.hash = self.sha1
                self.digestLen = 0x14
            elif hashtype == "SHA256":
                self.hash = self.sha256
                self.digestLen = 0x20

        def pss_test(self):
            N = "a2ba40ee07e3b2bd2f02ce227f36a195024486e49c19cb41bbbdfbba98b22b0e577c2eeaffa20d883a76e65e394c69d4b3c05a1e8fadda27edb2a42bc000fe888b9b32c22d15add0cd76b3e7936e19955b220dd17d4ea904b1ec102b2e4de7751222aa99151024c7cb41cc5ea21d00eeb41f7c800834d2c6e06bce3bce7ea9a5"
            e = "010001"
            D = "050e2c3e38d886110288dfc68a9533e7e12e27d2aa56d2cdb3fb6efa990bcff29e1d2987fb711962860e7391b1ce01ebadb9e812d2fbdfaf25df4ae26110a6d7a26f0b810f54875e17dd5c9fb6d641761245b81e79f8c88f0e55a6dcd5f133abd35f8f4ec80adf1bf86277a582894cb6ebcd2162f1c7534f1f4947b129151b71"
            MSG = "859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc"
            salt = "e3b5d5d002c1bce50c2b65ef88a188d83bce7e61"

            N = int(N, 16)
            e = int(e, 16)
            D = int(D, 16)
            MSG = unhexlify(MSG)
            salt = unhexlify(salt)
            signature = self.pss_sign(D, N, self.hash(MSG), salt, 1024)  # pkcs_1_pss_encode_sha256
            isvalid = self.pss_verify(e, N, self.hash(MSG), signature, 1024)
            if isvalid:
                print("Test passed.")
            else:
                print("Test failed.")

        def i2osp(self, x, x_len):
            '''Converts the integer x to its big-endian representation of length
               x_len.
            '''
            if x > 256 ** x_len:
                raise exceptions.IntegerTooLarge
            h = hex(x)[2:]
            if h[-1] == 'L':
                h = h[:-1]
            if len(h) & 1 == 1:
                h = '0%s' % h
            x = unhexlify(h)
            return b'\x00' * int(x_len - len(x)) + x

        def os2ip(self,x):
            '''Converts the byte string x representing an integer reprented using the
               big-endian convient to an integer.
            '''
            h = hexlify(x)
            return int(h, 16)

        #def os2ip(self, X):
        #    return int.from_bytes(X, byteorder='big')

        def mgf1(self, input, length):
            counter = 0
            output = b''
            while (len(output) < length):
                C = self.i2osp(counter, 4)
                output += self.hash(input + C)
                counter += 1
            return output[:length]

        def assert_int(self, var: int, name: str):
            if isinstance(var, int):
                return
            raise TypeError('%s should be an integer, not %s' % (name, var.__class__))

        def sign(self,tosign,D,N,emBits=1024):
            self.assert_int(tosign, 'message')
            self.assert_int(D, 'D')
            self.assert_int(N, 'n')

            if tosign < 0:
                raise ValueError('Only non-negative numbers are supported')

            if tosign > N:
                tosign1=divmod(tosign,N)[1]
                signature=pow(tosign1,D,N)
                raise OverflowError("The message %i is too long for n=%i" % (tosign, N))

            signature = pow(tosign, D, N)
            hexsign = self.i2osp(signature, emBits // 8)
            return hexsign

        def pss_sign(self, D, N, msghash, salt, emBits=1024):
            if isinstance(D,str):
                D=unhexlify(D)
                D=self.os2ip(D)
            if isinstance(N,str):
                N=unhexlify(N)
                N=self.os2ip(N)
            slen=len(salt)
            emLen = self.ceil_div(emBits, 8)
            inBlock = b"\x00" * 8 + msghash + salt
            hash = self.hash(inBlock)
            PSlen=emLen - self.digestLen - slen - 1 - 1
            DB = (PSlen * b"\x00") + b"\x01" + salt
            rlen = emLen - len(hash) - 1
            dbMask = self.mgf1(hash, rlen)
            maskedDB = bytearray()
            for i in range(0, len(dbMask)):
                maskedDB.append(dbMask[i] ^ DB[i])
            maskedDB[0]=maskedDB[0]&0x7F
            EM = maskedDB + hash + b"\xbc"
            tosign=self.os2ip(EM)
            #EM=hexlify(EM).decode('utf-8')
            #tosign = int(EM,16)
            return self.sign(tosign,D,N,emBits)
            #6B1EAA2042A5C8DA8B1B4A8320111A70A0CBA65233D1C6E418EF8156E82A8F96BD843F047FF25AB9702A6582C8387298753E628F23448B4580E09CBD2A483C623B888F47C4BD2C5EFF09013C6DFF67DB59BAB3037F0BEE05D5660264D28CC6251631FE75CE106D931A04FA032FEA31259715CE0FAB1AE0E2F8130807AF4019A61B9C060ECE59104F22156FEE8108F17DC80D7C2F8397AFB9780994F7C5A0652F93D1B48010B0B248AB9711235787D797FBA4D10A29BCF09628585D405640A866B15EE9D7526A2703E72A19811EF447F6E5C43F915B3808EBC79EA4BCF78903DBDE32E47E239CFB5F2B5986D0CBBFBE6BACDC29B2ADE006D23D0B90775B1AE4DD

        def ceil_div(self, a, b):
            (q, r) = divmod(a, b)
            if r:
                return q + 1
            else:
                return q

        def pss_verify(self, e, N, msghash, signature, emBits=1024, salt=None):
            if salt == None:
                slen = self.digestLen
            else:
                slen = len(salt)
            sig = self.os2ip(signature)

            EM = pow(sig, e, N)
            #EM = unhexlify(hex(EM)[2:])
            EM=self.i2osp(EM,emBits//8)

            emLen = len(signature)

            valBC = EM[-1]
            if valBC != 0xbc:
                return False
            hash = EM[emLen - self.digestLen - 1:-1]
            maskedDB = EM[:emLen - self.digestLen - 1]

            lmask=~(0xFF >> (8 * emLen + 1 - emBits))
            if EM[0]&lmask:
                return False


            dbMask = self.mgf1(hash, emLen - self.digestLen - 1)

            DB = bytearray()
            for i in range(0, len(dbMask)):
                DB.append(dbMask[i] ^ maskedDB[i])

            TS = bytearray()
            TS.append(DB[0] & ~lmask)
            TS.extend(DB[1:])

            PS = (b"\x00" * (emLen - self.digestLen - slen - 2)) + b"\x01"
            if TS[:len(PS)] != PS:
                print(TS[:len(PS)])
                print(PS)
                return False

            if salt != None:
                inBlock = b"\x00" * 8 + msghash + salt
                mhash = self.hash(inBlock)
                if mhash == hash:
                    return True
                else:
                    return False
            else:
                salt=TS[-self.digestLen:]
                inBlock = b"\x00" * 8 + msghash + salt
                mhash = self.hash(inBlock)
                if mhash == hash:
                    return True
                else:
                    return False
            return maskedDB

        def sha1(self, msg):
            return hashlib.sha1(msg).digest()

        def sha256(self, msg):
            return hashlib.sha256(msg).digest()

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
    qcdt_size_or_header_version=0
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
        param.qcdt_size_or_header_version = fields[9]
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

def get_next_modulus():
    rp = os.path.realpath(__file__)
    rp = rp[:rp.rfind("/")]
    rp = rp[:rp.rfind("/")]
    curpath = rp[:rp.rfind("/")]
    keydbname = os.path.join(curpath, "keys", "keys.json")
    with open(keydbname, "r") as rf:
        keydb = json.loads(rf.read())
        content = ""
        for key in keydb:
            if "modulus" in key:
                yield key["modulus"]

def extract_key(modulus,tmpdir):
    if modulus != "":
        modulus=modulus[:16]
        rp=os.path.realpath(__file__)
        rp=rp[:rp.rfind("/")]
        rp=rp[:rp.rfind("/")]
        curpath=rp[:rp.rfind("/")]
        keydbname=os.path.join(curpath,"keys","keys.json")
        datadbname=os.path.join(curpath,"keys","data.json")
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
