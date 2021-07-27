#!/usr/bin/env python3
# Dump Android Verified Boot Signature (c) B.Kerler 2017-2020
import hashlib
from binascii import hexlify,unhexlify
import sys
import argparse
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from root.scripts.Library.avbtool3 import *
from pyasn1.type import char, namedtype, univ
from pyasn1_modules import rfc2459
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from root.scripts.Library.utils import extract_key, get_next_modulus, rsa
import shutil
from struct import unpack, pack
version="v2.0"

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


class AuthenticatedAttributes(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('target', char.PrintableString()),
        namedtype.NamedType('length', univ.Integer())
    )

class BootSignature(univ.Sequence):
    """
    BootSignature ::= SEQUENCE {
        formatVersion ::= INTEGER
        certificate ::= Certificate
        algorithmIdentifier ::= SEQUENCE {
            algorithm OBJECT IDENTIFIER,
            parameters ANY DEFINED BY algorithm OPTIONAL
        }
        authenticatedAttributes ::= SEQUENCE {
            target CHARACTER STRING,
            length INTEGER
        }
        signature ::= OCTET STRING
    }
    """

    _FORMAT_VERSION = 1

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('formatVersion', univ.Integer()),
        namedtype.NamedType('certificate', rfc2459.Certificate()),
        namedtype.NamedType('algorithmIdentifier',
                            rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('authenticatedAttributes',
                            AuthenticatedAttributes()),
        namedtype.NamedType('signature', univ.OctetString())
    )

    @classmethod
    def create(cls, target, length):
        boot_signature = cls()
        boot_signature['formatVersion'] = cls._FORMAT_VERSION
        boot_signature['authenticatedAttributes']['target'] = target
        boot_signature['authenticatedAttributes']['length'] = length
        return boot_signature

def dump_signature(data):
    if data[0:2] == b'\x30\x82':
        der_items=der_decoder(data,BootSignature())
        publickey = der_items[0]["certificate"]["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"]
        publickey = int(str(publickey), 2).to_bytes((len(str(publickey)) + 7) // 8, 'big')
        signature = bytes(der_items[0]["signature"])
        name=der_items[0]['authenticatedAttributes']["target"]
        length = der_items[0]['authenticatedAttributes']["length"]

        '''
        slen = unpack('>H', data[2:4])[0]
        total = slen + 4
        cert = unpack('<%ds' % total, data[0:total])[0]

        der = DerSequence()
        der.decode(cert)

        cert0 = DerSequence()
        cert0.decode(bytes(der[1]))

        pk = DerSequence()
        pk.decode(bytes(cert0[0]))
        subjectPublicKeyInfo = pk[6]

        meta = DerSequence().decode(bytes(der[3]))
        name = meta[0][2:]
        length = meta[1]

        signature = bytes(der[4])[4:0x104]
        '''
        pub_key = RSA.importKey(publickey)
        hash=extract_hash(pub_key,signature)
        authenticated_attributes = der_items[0]['authenticatedAttributes']
        meta = der_encoder(authenticated_attributes)
        return [name,length,hash,pub_key,meta]
    else:
        return [None,None,None,None,None]

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
        fields = unpack('<8sIIIIIIIIII16s512s8I1024s', header)
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


def main(argv):
    info="Boot Signature Tool "+version+" (c) B.Kerler 2017-2021"
    print("\n"+info)
    print("----------------------------------------------")
    parser = argparse.ArgumentParser(description=info)
    parser.add_argument('--file','-f', dest='filename', default="", action='store', help='boot or recovery image filename')
    parser.add_argument('--vbmeta','-v', dest='vbmetaname', action='store', default='', help='vbmeta partition')
    parser.add_argument('--length', '-l', dest='inject', action='store_true', default=False, help='adapt signature length')
    args = parser.parse_args()
    rs=rsa()
    if args.filename=="":
        print("Usage: verify_signature.py -f [boot.img]")
        exit(0)
    param=getheader(args.filename)
    kernelsize = int((param.kernel_size + param.page_size - 1) / param.page_size) * param.page_size
    ramdisksize = int((param.ramdisk_size + param.page_size - 1) / param.page_size) * param.page_size
    secondsize = int((param.second_size + param.page_size - 1) / param.page_size) * param.page_size
    qcdtsize = int((param.qcdt_size_or_header_version + param.page_size - 1) / param.page_size) * param.page_size
    
    print("Kernel=0x%08X,\tlength=0x%08X" % (param.page_size, kernelsize))
    print("Ramdisk=0x%08X,\tlength=0x%08X" % ((param.page_size+kernelsize),ramdisksize))
    print("Second=0x%08X,\tlength=0x%08X" % ((param.page_size+kernelsize+ramdisksize),secondsize))
    print("QCDT=0x%08X,\tlength=0x%08X" % ((param.page_size+kernelsize+ramdisksize+secondsize),qcdtsize))
    if qcdtsize==2048:
        qcdtsize=0 #MTK fix
    length=param.page_size+kernelsize+ramdisksize+secondsize+qcdtsize
    print("Signature start=0x%08X" % length)

    with open(args.filename,'rb') as fr:
        data=fr.read()
        filesize=os.stat(args.filename).st_size
        footerpos=(filesize//0x1000*0x1000)-AvbFooter.SIZE
        if data[footerpos:footerpos+4]==b"AVBf":
            ftr=AvbFooter(data[footerpos:footerpos+AvbFooter.SIZE])
            signature=data[ftr.vbmeta_offset:]
            data=data[0:ftr.vbmeta_offset]
            avbhdr=AvbVBMetaHeader(signature[:AvbVBMetaHeader.SIZE])
            release_string=avbhdr.release_string.replace(b"\x00",b"").decode('utf-8')
            print(f"\nAVB >=2.0 vbmeta detected: {release_string}\n----------------------------------------")
            if " 1.0" not in release_string and " 1.1" not in release_string:
                print("Sorry, only avb version <=1.1 is currently implemented")
                exit(0)
            hashdata=signature[avbhdr.SIZE+avbhdr.authentication_data_block_size:]
            imgavbhash=AvbHashDescriptor(hashdata)
            print("Image-Target: \t\t\t\t" + str(imgavbhash.partition_name.decode('utf-8')))
            # digest_size = len(hashlib.new(name=avbhash.hash_algorithm).digest())
            # digest_padding = round_to_pow2(digest_size) - digest_size
            # block_size=4096
            # (hash_level_offsets, tree_size) = calc_hash_level_offsets(avbhash.image_size, block_size, digest_size + digest_padding)
            # root_digest, hash_tree = generate_hash_tree(fr, avbhash.image_size, block_size, avbhash.hash_algorithm, avbhash.salt, digest_padding, hash_level_offsets, tree_size)

            ctx=hashlib.new(name=imgavbhash.hash_algorithm.decode('utf-8'))
            ctx.update(imgavbhash.salt)
            ctx.update(data[:imgavbhash.image_size])
            root_digest=ctx.digest()
            print("Salt: \t\t\t\t\t\t" + str(hexlify(imgavbhash.salt).decode('utf-8')))
            print("Image-Size: \t\t\t\t" + hex(imgavbhash.image_size))
            img_digest=str(hexlify(root_digest).decode('utf-8'))
            img_avb_digest=str(hexlify(imgavbhash.digest).decode('utf-8'))
            print("\nCalced Image-Hash: \t\t\t" + img_digest)
            #print("Calced Hash_Tree: " + str(binascii.hexlify(hash_tree)))
            print("Image-Hash: \t\t\t\t" + img_avb_digest)
            avbmetacontent={}
            vbmeta=None
            if args.vbmetaname=="":
                if os.path.exists("vbmeta.img"):
                    args.vbmetaname="vbmeta.img"
            if args.vbmetaname!="":
                with open(args.vbmetaname,'rb') as vbm:
                    vbmeta=vbm.read()
                    if vbmeta[:4]==b"DHTB":
                        print("!!!! Detected Spreadtrum special hash header !!!!")
                        print("SHA256-Hash :\t\t\t\t"+hexlify(vbmeta[8:0x28]).decode('utf-8'))
                        length=unpack("<I",vbmeta[0x30:0x34])[0]
                        vbmeta=vbmeta[0x200:0x200+length]
                        calcedhash=hashlib.sha256(vbmeta).digest()
                        print("Calced Hash :\t\t\t\t"+hexlify(calcedhash).decode('utf-8'))
                    else:
                        idx=vbmeta.find(b"AVB0")
                        if idx!=-1:
                            vbmeta=vbmeta[idx:]
                    avbhdr=AvbVBMetaHeader(vbmeta[:AvbVBMetaHeader.SIZE])
                    if avbhdr.magic!=b'AVB0':
                        print("Unknown vbmeta data")
                        exit(0)
                    class authentication_data(object):
                        def __init__(self,hdr,data):
                            self.hash=data[0x100+hdr.hash_offset:0x100+hdr.hash_offset+hdr.hash_size]
                            self.signature=data[0x100+hdr.signature_offset:0x100+hdr.signature_offset+hdr.signature_size]

                    class auxilary_data(object):
                        def __init__(self, hdr, data):
                            self.data=data[0x100+hdr.authentication_data_block_size:0x100+hdr.authentication_data_block_size+hdr.auxiliary_data_block_size]

                    authdata=authentication_data(avbhdr,vbmeta)
                    auxdata=auxilary_data(avbhdr,vbmeta).data

                    auxlen=len(auxdata)
                    i=0
                    while (i<auxlen):
                        desc=AvbDescriptor(auxdata[i:])
                        data=auxdata[i:]
                        if desc.tag==AvbPropertyDescriptor.TAG:
                            avbproperty=AvbPropertyDescriptor(data)
                            avbmetacontent["property"]=dict(avbproperty=avbproperty)
                        elif desc.tag==AvbHashtreeDescriptor.TAG:
                            avbhashtree=AvbHashtreeDescriptor(data)
                            partition_name=avbhashtree.partition_name
                            salt=avbhashtree.salt
                            root_digest=avbhashtree.root_digest
                            avbmetacontent[partition_name]=dict(salt=salt,root_digest=root_digest)
                        elif desc.tag==AvbHashDescriptor.TAG:
                            avbhash=AvbHashDescriptor(data)
                            partition_name=avbhash.partition_name
                            salt=avbhash.salt
                            digest=avbhash.digest
                            avbmetacontent[partition_name] = dict(salt=salt,digest=digest)
                        elif desc.tag==AvbKernelCmdlineDescriptor.TAG:
                            avbcmdline=AvbKernelCmdlineDescriptor(data)
                            kernel_cmdline=avbcmdline.kernel_cmdline
                            avbmetacontent["cmdline"] = dict(kernel_cmdline=kernel_cmdline)
                        elif desc.tag==AvbChainPartitionDescriptor.TAG:
                            avbchainpartition=AvbChainPartitionDescriptor(data)
                            partition_name=avbchainpartition.partition_name
                            public_key=avbchainpartition.public_key
                            avbmetacontent[partition_name] = dict(public_key=public_key)
                        i += desc.SIZE+len(desc.data)

            vbmeta_digest=None
            if imgavbhash.partition_name in avbmetacontent:
                if "digest" in avbmetacontent[imgavbhash.partition_name]:
                    digest=avbmetacontent[imgavbhash.partition_name]["digest"]
                    vbmeta_digest = str(hexlify(digest).decode('utf-8'))
                    print("VBMeta-Image-Hash: \t\t\t" + vbmeta_digest)
            else:
                print("Couldn't find "+imgavbhash.partition_name+" in "+args.vbmetaname)
                exit(0)

            if vbmeta!=None:
                pubkeydata=vbmeta[AvbVBMetaHeader.SIZE+avbhdr.authentication_data_block_size+avbhdr.public_key_offset:
                                  AvbVBMetaHeader.SIZE+avbhdr.authentication_data_block_size+avbhdr.public_key_offset
                                  +avbhdr.public_key_size]
                modlen = unpack(">I",pubkeydata[:4])[0]//4
                n0inv = unpack(">I", pubkeydata[4:8])[0]
                modulus=hexlify(pubkeydata[8:8+modlen]).decode('utf-8')
                print("\nSignature-RSA-Modulus (n):\t"+modulus)
                print("Signature-n0inv: \t\t\t" + str(n0inv))
                KEYPATH = "key"
                if (os.path.exists(KEYPATH)):
                    shutil.rmtree(KEYPATH)
                os.mkdir(KEYPATH)
                if os.path.exists("key"):
                    keyname = extract_key(modulus, KEYPATH)
                    if keyname:
                        print(f"\nKey found: {keyname}")
            else:
                print("VBMeta info missing... please copy vbmeta.img to the directory.")
            state=3
            if img_digest==img_avb_digest:
                state=0
                if vbmeta_digest!=None:
                    if vbmeta_digest==img_digest:
                        state=0
                    else:
                        state=3
            rotstate(state)

            exit(0)
        else:
            signature=data[length:]
            data=data[:length]
            sha256 = hashlib.sha256()
            sha256.update(data)
            found=False
            try:
                target,siglength,hash,pub_key,meta=dump_signature(signature)
                if hash!=None:
                    found = 1
            except:
                print("No signature found :/")
                exit(0)
            if hash==None:
                siglength=len(signature)
                meta=b""
                for modulus in get_next_modulus():
                    llen=len(modulus)//2
                    modulus = int(modulus, 16)
                    #encrypted = int(hexlify(signature), 16)
                    exponent=0x10001
                    digest=sha256.digest()
                    isvalid = rs.pss_verify(exponent, modulus, digest, signature, llen*8)
                    if isvalid==True:
                        hash=digest
                        found=2
                        break

            id=hexlify(data[576:576+32])
            print("\nID: "+id.decode('utf-8'))
            print("Image-Target: "+str(target))
            print("Image-Size: "+hex(length))
            print("Signature-Size: "+hex(siglength))
            #meta=b"\x30"+flag+b"\x13"+bytes(pack('B',len(target)))+bytes(target)+b"\x02\x03"+bytes(pack(">I",length)[1:4])
            #print(meta)
            if found<2:
                sha256.update(meta)
                digest=sha256.digest()
            print("\nCalced Image-Hash:\t"+hexlify(digest).decode('utf8'))
            if found>0:
                print("Signature-Hash:\t\t" + hexlify(hash).decode('utf8'))
                if str(hexlify(digest))==str(hexlify(hash)):
                    rotstate(0)
                else:
                    rotstate(3)
                if found==1:
                    modulus=int_to_bytes(pub_key.n)
                    exponent=int_to_bytes(pub_key.e)
                else:
                    modulus = int_to_bytes(modulus)
                    exponent=int_to_bytes(exponent)
                smod=str(hexlify(modulus).decode('utf-8'))
                print("\nSignature-RSA-Modulus (n):\t"+smod)
                print("Signature-RSA-Exponent (e):\t" + str(hexlify(exponent).decode('utf-8')))
                KEYPATH = "key"
                if (os.path.exists(KEYPATH)):
                    shutil.rmtree(KEYPATH)
                os.mkdir(KEYPATH)
                if os.path.exists("key"):
                    keyname = extract_key(hexlify(modulus).decode('utf-8'), KEYPATH)
                    if keyname:
                        print(f"\nKey found: {keyname}")
                sha256 = hashlib.sha256()
                sha256.update(modulus+exponent)
                pubkey_hash=sha256.digest()
                locked=pubkey_hash+pack('<I',0x0)
                unlocked = pubkey_hash + pack('<I', 0x1)
                sha256 = hashlib.sha256()
                sha256.update(locked)
                root_of_trust_locked=sha256.digest()
                sha256 = hashlib.sha256()
                sha256.update(unlocked)
                root_of_trust_unlocked=sha256.digest()
                print("\nTZ Root of trust (locked):\t\t" + str(hexlify(root_of_trust_locked).decode('utf-8')))
                print("TZ Root of trust (unlocked):\t" + str(hexlify(root_of_trust_unlocked).decode('utf-8')))

    if (args.inject==True):
        pos = signature.find(target)
        if (pos != -1):
            lenpos = signature.find(pack(">I",length)[0],pos)
            if (lenpos!=-1):
                with open(args.filename[0:-4]+"_signed.bin",'wb') as wf:
                    wf.write(data)
                    wf.write(signature[0:lenpos])
                    wf.write(pack(">I",length))
                    wf.write(signature[lenpos+4:])
                    print("Successfully injected !")

if __name__ == "__main__":
   main(sys.argv[1:])
