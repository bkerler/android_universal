import hashlib
import struct
import sys
import os
import bisect
import math
import subprocess
import tempfile

AVB_FOOTER_VERSION_MAJOR=1
AVB_FOOTER_VERSION_MINOR=1

MAX_VBMETA_SIZE = 64 * 1024
MAX_FOOTER_SIZE = 4096

# Keep in sync with libavb/avb_version.h.
AVB_VERSION_MAJOR = 1
AVB_VERSION_MINOR = 1
AVB_VERSION_SUB = 0


def _parse_image(image):
    """Gets information about an image.

    The image can either be a vbmeta or an image with a footer.

    Arguments:
      image: An ImageHandler (vbmeta or footer) with a hashtree descriptor.

    Returns:
      A tuple where the first argument is a AvbFooter (None if there
      is no footer on the image), the second argument is a
      AvbVBMetaHeader, the third argument is a list of
      AvbDescriptor-derived instances, and the fourth argument is the
      size of |image|.
    """
    assert isinstance(image, ImageHandler)
    footer = None
    image.seek(image.image_size - AvbFooter.SIZE)
    try:
        footer = AvbFooter(image.read(AvbFooter.SIZE))
    except (LookupError, struct.error):
        # Nope, just seek back to the start.
        image.seek(0)

    vbmeta_offset = 0
    if footer:
        vbmeta_offset = footer.vbmeta_offset

    image.seek(vbmeta_offset)
    h = AvbVBMetaHeader(image.read(AvbVBMetaHeader.SIZE))

    auth_block_offset = vbmeta_offset + AvbVBMetaHeader.SIZE
    aux_block_offset = auth_block_offset + h.authentication_data_block_size
    desc_start_offset = aux_block_offset + h.descriptors_offset
    image.seek(desc_start_offset)
    descriptors = parse_descriptors(image.read(h.descriptors_size))

    return footer, h, descriptors, image.image_size

def get_release_string():
  """Calculates the release string to use in the VBMeta struct."""
  # Keep in sync with libavb/avb_version.c:avb_version_string().
  return bytes('avbtool {}.{}.{}'.format(AVB_VERSION_MAJOR,
                                   AVB_VERSION_MINOR,
                                   AVB_VERSION_SUB),'utf-8')
class Algorithm(object):
  """Contains details about an algorithm.

  See the avb_vbmeta_image.h file for more details about algorithms.

  The constant |ALGORITHMS| is a dictionary from human-readable
  names (e.g 'SHA256_RSA2048') to instances of this class.

  Attributes:
    algorithm_type: Integer code corresponding to |AvbAlgorithmType|.
    hash_name: Empty or a name from |hashlib.algorithms|.
    hash_num_bytes: Number of bytes used to store the hash.
    signature_num_bytes: Number of bytes used to store the signature.
    public_key_num_bytes: Number of bytes used to store the public key.
    padding: Padding used for signature, if any.
  """

  def __init__(self, algorithm_type, hash_name, hash_num_bytes,
               signature_num_bytes, public_key_num_bytes, padding):
    self.algorithm_type = algorithm_type
    self.hash_name = hash_name
    self.hash_num_bytes = hash_num_bytes
    self.signature_num_bytes = signature_num_bytes
    self.public_key_num_bytes = public_key_num_bytes
    self.padding = padding

# This must be kept in sync with the avb_crypto.h file.
#
# The PKC1-v1.5 padding is a blob of binary DER of ASN.1 and is
# obtained from section 5.2.2 of RFC 4880.
ALGORITHMS = {
    'NONE': Algorithm(
        algorithm_type=0,        # AVB_ALGORITHM_TYPE_NONE
        hash_name='',
        hash_num_bytes=0,
        signature_num_bytes=0,
        public_key_num_bytes=0,
        padding=[]),
    'SHA256_RSA2048': Algorithm(
        algorithm_type=1,        # AVB_ALGORITHM_TYPE_SHA256_RSA2048
        hash_name='sha256',
        hash_num_bytes=32,
        signature_num_bytes=256,
        public_key_num_bytes=8 + 2*2048/8,
        padding=[
            # PKCS1-v1_5 padding
            0x00, 0x01] + [0xff]*202 + [0x00] + [
                # ASN.1 header
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            ]),
    'SHA256_RSA4096': Algorithm(
        algorithm_type=2,        # AVB_ALGORITHM_TYPE_SHA256_RSA4096
        hash_name='sha256',
        hash_num_bytes=32,
        signature_num_bytes=512,
        public_key_num_bytes=8 + 2*4096/8,
        padding=[
            # PKCS1-v1_5 padding
            0x00, 0x01] + [0xff]*458 + [0x00] + [
                # ASN.1 header
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            ]),
    'SHA256_RSA8192': Algorithm(
        algorithm_type=3,        # AVB_ALGORITHM_TYPE_SHA256_RSA8192
        hash_name='sha256',
        hash_num_bytes=32,
        signature_num_bytes=1024,
        public_key_num_bytes=8 + 2*8192/8,
        padding=[
            # PKCS1-v1_5 padding
            0x00, 0x01] + [0xff]*970 + [0x00] + [
                # ASN.1 header
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            ]),
    'SHA512_RSA2048': Algorithm(
        algorithm_type=4,        # AVB_ALGORITHM_TYPE_SHA512_RSA2048
        hash_name='sha512',
        hash_num_bytes=64,
        signature_num_bytes=256,
        public_key_num_bytes=8 + 2*2048/8,
        padding=[
            # PKCS1-v1_5 padding
            0x00, 0x01] + [0xff]*170 + [0x00] + [
                # ASN.1 header
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                0x00, 0x04, 0x40
            ]),
    'SHA512_RSA4096': Algorithm(
        algorithm_type=5,        # AVB_ALGORITHM_TYPE_SHA512_RSA4096
        hash_name='sha512',
        hash_num_bytes=64,
        signature_num_bytes=512,
        public_key_num_bytes=8 + 2*4096/8,
        padding=[
            # PKCS1-v1_5 padding
            0x00, 0x01] + [0xff]*426 + [0x00] + [
                # ASN.1 header
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                0x00, 0x04, 0x40
            ]),
    'SHA512_RSA8192': Algorithm(
        algorithm_type=6,        # AVB_ALGORITHM_TYPE_SHA512_RSA8192
        hash_name='sha512',
        hash_num_bytes=64,
        signature_num_bytes=1024,
        public_key_num_bytes=8 + 2*8192/8,
        padding=[
            # PKCS1-v1_5 padding
            0x00, 0x01] + [0xff]*938 + [0x00] + [
                # ASN.1 header
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                0x00, 0x04, 0x40
            ]),
}


def _get_cmdline_descriptors_for_hashtree_descriptor(ht):
    """Generate kernel cmdline descriptors for dm-verity.

    Arguments:
      ht: A AvbHashtreeDescriptor

    Returns:
      A list with two AvbKernelCmdlineDescriptor with dm-verity kernel cmdline
      instructions. There is one for when hashtree is not disabled and one for
      when it is.

    """

    c = 'dm="1 vroot none ro 1,'
    c += '0'  # start
    c += ' {}'.format((ht.image_size / 512))  # size (# sectors)
    c += ' verity {}'.format(ht.dm_verity_version)  # type and version
    c += ' PARTUUID=$(ANDROID_SYSTEM_PARTUUID)'  # data_dev
    c += ' PARTUUID=$(ANDROID_SYSTEM_PARTUUID)'  # hash_dev
    c += ' {}'.format(ht.data_block_size)  # data_block
    c += ' {}'.format(ht.hash_block_size)  # hash_block
    c += ' {}'.format(ht.image_size / ht.data_block_size)  # #blocks
    c += ' {}'.format(ht.image_size / ht.data_block_size)  # hash_offset
    c += ' {}'.format(ht.hash_algorithm)  # hash_alg
    c += ' {}'.format(str(ht.root_digest).encode('hex'))  # root_digest
    c += ' {}'.format(str(ht.salt).encode('hex'))  # salt
    if ht.fec_num_roots > 0:
        c += ' 10'  # number of optional args
        c += ' $(ANDROID_VERITY_MODE)'
        c += ' ignore_zero_blocks'
        c += ' use_fec_from_device PARTUUID=$(ANDROID_SYSTEM_PARTUUID)'
        c += ' fec_roots {}'.format(ht.fec_num_roots)
        # Note that fec_blocks is the size that FEC covers, *not* the
        # size of the FEC data. Since we use FEC for everything up until
        # the FEC data, it's the same as the offset.
        c += ' fec_blocks {}'.format(ht.fec_offset / ht.data_block_size)
        c += ' fec_start {}'.format(ht.fec_offset / ht.data_block_size)
    else:
        c += ' 2'  # number of optional args
        c += ' $(ANDROID_VERITY_MODE)'
        c += ' ignore_zero_blocks'
    c += '" root=/dev/dm-0'

    # Now that we have the command-line, generate the descriptor.
    desc = AvbKernelCmdlineDescriptor()
    desc.kernel_cmdline = c
    desc.flags = (
        AvbKernelCmdlineDescriptor.FLAGS_USE_ONLY_IF_HASHTREE_NOT_DISABLED)

    # The descriptor for when hashtree verification is disabled is a lot
    # simpler - we just set the root to the partition.
    desc_no_ht = AvbKernelCmdlineDescriptor()
    desc_no_ht.kernel_cmdline = 'root=PARTUUID=$(ANDROID_SYSTEM_PARTUUID)'
    desc_no_ht.flags = (
        AvbKernelCmdlineDescriptor.FLAGS_USE_ONLY_IF_HASHTREE_DISABLED)

    return [desc, desc_no_ht]


def _get_cmdline_descriptors_for_dm_verity(image):
    """Generate kernel cmdline descriptors for dm-verity.

    Arguments:
      image: An ImageHandler (vbmeta or footer) with a hashtree descriptor.

    Returns:
      A list with two AvbKernelCmdlineDescriptor with dm-verity kernel cmdline
      instructions. There is one for when hashtree is not disabled and one for
      when it is.

    Raises:
      AvbError: If  |image| doesn't have a hashtree descriptor.

    """

    (_, _, descriptors, _) = _parse_image(image)

    ht = None
    for desc in descriptors:
        if isinstance(desc, AvbHashtreeDescriptor):
            ht = desc
            break

    if not ht:
        raise AvbError('No hashtree descriptor in given image')

    return _get_cmdline_descriptors_for_hashtree_descriptor(ht)

class RSAPublicKey(object):
  """Data structure used for a RSA public key.

  Attributes:
    exponent: The key exponent.
    modulus: The key modulus.
    num_bits: The key size.
  """

  MODULUS_PREFIX = b'modulus='

  def __init__(self, key_path):
    """Loads and parses an RSA key from either a private or public key file.

    Arguments:
      key_path: The path to a key file.
    """
    # We used to have something as simple as this:
    #
    #  key = Crypto.PublicKey.RSA.importKey(open(key_path).read())
    #  self.exponent = key.e
    #  self.modulus = key.n
    #  self.num_bits = key.size() + 1
    #
    # but unfortunately PyCrypto is not available in the builder. So
    # instead just parse openssl(1) output to get this
    # information. It's ugly but...
    args = ['openssl', 'rsa', '-in', key_path, '-modulus', '-noout']
    p = subprocess.Popen(args,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (pout, perr) = p.communicate()
    if p.wait() != 0:
      # Could be just a public key is passed, try that.
      args.append('-pubin')
      p = subprocess.Popen(args,
                           stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
      (pout, perr) = p.communicate()
      if p.wait() != 0:
        raise AvbError('Error getting public key: {}'.format(perr))

    if not pout.lower().startswith(self.MODULUS_PREFIX):
      raise AvbError('Unexpected modulus output')

    modulus_hexstr = pout[len(self.MODULUS_PREFIX):]

    # The exponent is assumed to always be 65537 and the number of
    # bits can be derived from the modulus by rounding up to the
    # nearest power of 2.
    self.modulus = int(modulus_hexstr, 16)
    self.num_bits = round_to_pow2(int(math.ceil(math.log(self.modulus, 2))))
    self.exponent = 65537


def egcd(a, b):
  """Calculate greatest common divisor of two numbers.

  This implementation uses a recursive version of the extended
  Euclidian algorithm.

  Arguments:
    a: First number.
    b: Second number.

  Returns:
    A tuple (gcd, x, y) that where |gcd| is the greatest common
    divisor of |a| and |b| and |a|*|x| + |b|*|y| = |gcd|.
  """
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
  """Calculate modular multiplicative inverse of |a| modulo |m|.

  This calculates the number |x| such that |a| * |x| == 1 (modulo
  |m|). This number only exists if |a| and |m| are co-prime - |None|
  is returned if this isn't true.

  Arguments:
    a: The number to calculate a modular inverse of.
    m: The modulo to use.

  Returns:
    The modular multiplicative inverse of |a| and |m| or |None| if
    these numbers are not co-prime.
  """
  gcd, x, _ = egcd(a, m)
  if gcd != 1:
    return None  # modular inverse does not exist
  else:
    return x % m

def encode_long(num_bits, value):
  """Encodes a long to a bytearray() using a given amount of bits.

  This number is written big-endian, e.g. with the most significant
  bit first.

  This is the reverse of decode_long().

  Arguments:
    num_bits: The number of bits to write, e.g. 2048.
    value: The value to write.

  Returns:
    A bytearray() with the encoded long.
  """
  ret = bytearray()
  for bit_pos in range(num_bits, 0, -8):
    octet = (value >> (bit_pos - 8)) & 0xff
    ret.extend(struct.pack('!B', octet))
  return ret

def encode_rsa_key(key_path):
  """Encodes a public RSA key in |AvbRSAPublicKeyHeader| format.

  This creates a |AvbRSAPublicKeyHeader| as well as the two large
  numbers (|key_num_bits| bits long) following it.

  Arguments:
    key_path: The path to a key file.

  Returns:
    A bytearray() with the |AvbRSAPublicKeyHeader|.
  """
  key = RSAPublicKey(key_path)
  if key.exponent != 65537:
    raise AvbError('Only RSA keys with exponent 65537 are supported.')
  ret = bytearray()
  # Calculate n0inv = -1/n[0] (mod 2^32)
  b = 2**32
  n0inv = b - modinv(key.modulus, b)
  # Calculate rr = r^2 (mod N), where r = 2^(# of key bits)
  r = 2**key.modulus.bit_length()
  rrmodn = r * r % key.modulus
  ret.extend(struct.pack('!II', key.num_bits, n0inv))
  ret.extend(encode_long(key.num_bits, key.modulus))
  ret.extend(encode_long(key.num_bits, rrmodn))
  return ret

def raw_sign(signing_helper, signing_helper_with_files,
             algorithm_name, signature_num_bytes, key_path,
             raw_data_to_sign):
  """Computes a raw RSA signature using |signing_helper| or openssl.

  Arguments:
    signing_helper: Program which signs a hash and returns the signature.
    signing_helper_with_files: Same as signing_helper but uses files instead.
    algorithm_name: The algorithm name as per the ALGORITHMS dict.
    signature_num_bytes: Number of bytes used to store the signature.
    key_path: Path to the private key file. Must be PEM format.
    raw_data_to_sign: Data to sign (bytearray or str expected).

  Returns:
    A bytearray containing the signature.

  Raises:
    Exception: If an error occurs.
  """
  p = None
  if signing_helper_with_files is not None:
    signing_file = tempfile.NamedTemporaryFile()
    signing_file.write(raw_data_to_sign)
    signing_file.flush()
    p = subprocess.Popen(
      [signing_helper_with_files, algorithm_name, key_path, signing_file.name])
    retcode = p.wait()
    if retcode != 0:
      raise AvbError('Error signing')
    signing_file.seek(0)
    signature = bytearray(signing_file.read())
  else:
    if signing_helper is not None:
      p = subprocess.Popen(
          [signing_helper, algorithm_name, key_path],
          stdin=subprocess.PIPE,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE)
    else:
      p = subprocess.Popen(
          ['openssl', 'rsautl', '-sign', '-inkey', key_path, '-raw'],
          stdin=subprocess.PIPE,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE)
    (pout, perr) = p.communicate(raw_data_to_sign)
    retcode = p.wait()
    if retcode != 0:
      raise AvbError('Error signing: {}'.format(perr))
    signature = bytearray(pout)
  if len(signature) != signature_num_bytes:
    raise AvbError('Error signing: Invalid length of signature')
  return signature


def _generate_vbmeta_blob(algorithm_name, key_path,
                          public_key_metadata_path, descriptors,
                          chain_partitions,
                          rollback_index, flags, props, props_from_file,
                          kernel_cmdlines,
                          setup_rootfs_from_kernel,
                          ht_desc_to_setup,
                          include_descriptors_from_image, signing_helper,
                          signing_helper_with_files,
                          release_string, append_to_release_string,
                          required_libavb_version_minor):
    """Generates a VBMeta blob.

    This blob contains the header (struct AvbVBMetaHeader), the
    authentication data block (which contains the hash and signature
    for the header and auxiliary block), and the auxiliary block
    (which contains descriptors, the public key used, and other data).

    The |key| parameter can |None| only if the |algorithm_name| is
    'NONE'.

    Arguments:
      algorithm_name: The algorithm name as per the ALGORITHMS dict.
      key_path: The path to the .pem file used to sign the blob.
      public_key_metadata_path: Path to public key metadata or None.
      descriptors: A list of descriptors to insert or None.
      chain_partitions: List of partitions to chain or None.
      rollback_index: The rollback index to use.
      flags: Flags to use in the image.
      props: Properties to insert (List of strings of the form 'key:value').
      props_from_file: Properties to insert (List of strings 'key:<path>').
      kernel_cmdlines: Kernel cmdlines to insert (list of strings).
      setup_rootfs_from_kernel: None or file to generate
        dm-verity kernel cmdline from.
      ht_desc_to_setup: If not None, an AvbHashtreeDescriptor to
        generate dm-verity kernel cmdline descriptors from.
      include_descriptors_from_image: List of file objects for which
        to insert descriptors from.
      signing_helper: Program which signs a hash and return signature.
      signing_helper_with_files: Same as signing_helper but uses files instead.
      release_string: None or avbtool release string.
      append_to_release_string: None or string to append.
      required_libavb_version_minor: Use at least this required minor version.

    Returns:
      A bytearray() with the VBMeta blob.

    Raises:
      Exception: If the |algorithm_name| is not found, if no key has
        been given and the given algorithm requires one, or the key is
        of the wrong size.

    """
    try:
        alg = ALGORITHMS[algorithm_name]
    except KeyError:
        raise AvbError('Unknown algorithm with name {}'.format(algorithm_name))

    if not descriptors:
        descriptors = []

    h = AvbVBMetaHeader()
    h.bump_required_libavb_version_minor(required_libavb_version_minor)

    # Insert chained partition descriptors, if any
    if chain_partitions:
        used_locations = {}
        for cp in chain_partitions:
            cp_tokens = cp.split(':')
            if len(cp_tokens) != 3:
                raise AvbError('Malformed chained partition "{}".'.format(cp))
            partition_name = cp_tokens[0]
            rollback_index_location = int(cp_tokens[1])
            file_path = cp_tokens[2]
            # Check that the same rollback location isn't being used by
            # multiple chained partitions.
            if used_locations.get(rollback_index_location):
                raise AvbError('Rollback Index Location {} is already in use.'.format(
                    rollback_index_location))
            used_locations[rollback_index_location] = True
            desc = AvbChainPartitionDescriptor()
            desc.partition_name = partition_name
            desc.rollback_index_location = rollback_index_location
            if desc.rollback_index_location < 1:
                raise AvbError('Rollback index location must be 1 or larger.')
            desc.public_key = open(file_path, 'rb').read()
            descriptors.append(desc)

    # Descriptors.
    encoded_descriptors = bytearray()

    for desc in descriptors:
        encoded_descriptors.extend(desc.encode())

    # Add properties.
    if props:
        for prop in props:
            idx = prop.find(':')
            if idx == -1:
                raise AvbError('Malformed property "{}".'.format(prop))
            desc = AvbPropertyDescriptor()
            desc.key = prop[0:idx]
            desc.value = prop[(idx + 1):]
            encoded_descriptors.extend(desc)
    if props_from_file:
        for prop in props_from_file:
            idx = prop.find(':')
            if idx == -1:
                raise AvbError('Malformed property "{}".'.format(prop))
            desc = AvbPropertyDescriptor()
            desc.key = prop[0:idx]
            desc.value = prop[(idx + 1):]
            file_path = prop[(idx + 1):]
            desc.value = open(file_path, 'rb').read()
            encoded_descriptors.extend(desc)

    # Add AvbKernelCmdline descriptor for dm-verity from an image, if requested.
    if setup_rootfs_from_kernel:
        image_handler = ImageHandler(
            setup_rootfs_from_kernel.name)
        cmdline_desc = _get_cmdline_descriptors_for_dm_verity(image_handler)
        encoded_descriptors.extend(cmdline_desc[0])
        encoded_descriptors.extend(cmdline_desc[1])

    # Add AvbKernelCmdline descriptor for dm-verity from desc, if requested.
    if ht_desc_to_setup:
        cmdline_desc = _get_cmdline_descriptors_for_hashtree_descriptor(
            ht_desc_to_setup)
        encoded_descriptors.extend(cmdline_desc[0])
        encoded_descriptors.extend(cmdline_desc[1])

    # Add kernel command-lines.
    if kernel_cmdlines:
        for i in kernel_cmdlines:
            desc = AvbKernelCmdlineDescriptor()
            desc.kernel_cmdline = bytes(i, 'utf-8')
            encoded_descriptors.extend(desc.encode())

    # Add descriptors from other images.
    if include_descriptors_from_image:
        descriptors_dict = dict()
        for image in include_descriptors_from_image:
            image_handler = ImageHandler(image)
            (_, image_vbmeta_header, image_descriptors, _) = _parse_image(
                image_handler)
            # Bump the required libavb version to support all included descriptors.
            h.bump_required_libavb_version_minor(
                image_vbmeta_header.required_libavb_version_minor)
            for desc in image_descriptors:
                # The --include_descriptors_from_image option is used in some setups
                # with images A and B where both A and B contain a descriptor
                # for a partition with the same name. Since it's not meaningful
                # to include both descriptors, only include the last seen descriptor.
                # See bug 76386656 for details.
                if hasattr(desc, 'partition_name'):
                    found=False
                    for desc2 in descriptors:
                        if hasattr(desc2,'partition_name'):
                            if bytes(desc.partition_name,'utf-8')==desc2.partition_name:
                                found=True
                    if not found:
                        key = type(desc).__name__ + '_' + desc.partition_name
                        descriptors_dict[key] = desc
                else:
                    encoded_descriptors.extend(desc.encode())
        for key in sorted(descriptors_dict.keys()):
            encoded_descriptors.extend(descriptors_dict[key].encode())

    # Load public key metadata blob, if requested.
    pkmd_blob = []
    if public_key_metadata_path:
        with open(public_key_metadata_path) as f:
            pkmd_blob = f.read()

    key = None
    encoded_key = bytearray()
    if alg.public_key_num_bytes > 0:
        if not key_path:
            raise AvbError('Key is required for algorithm {}'.format(
                algorithm_name))
        encoded_key = encode_rsa_key(key_path)
        if len(encoded_key) != alg.public_key_num_bytes:
            raise AvbError('Key is wrong size for algorithm {}'.format(
                algorithm_name))

    # Override release string, if requested.
    if isinstance(release_string, bytes):
        h.release_string = release_string

    # Append to release string, if requested. Also insert a space before.
    if isinstance(append_to_release_string, bytes):
        h.release_string += ' ' + append_to_release_string

    # For the Auxiliary data block, descriptors are stored at offset 0,
    # followed by the public key, followed by the public key metadata blob.
    h.auxiliary_data_block_size = round_to_multiple(
        len(encoded_descriptors) + len(encoded_key) + len(pkmd_blob), 64)
    h.descriptors_offset = 0
    h.descriptors_size = len(encoded_descriptors)
    h.public_key_offset = h.descriptors_size
    h.public_key_size = len(encoded_key)
    h.public_key_metadata_offset = h.public_key_offset + h.public_key_size
    h.public_key_metadata_size = len(pkmd_blob)

    # For the Authentication data block, the hash is first and then
    # the signature.
    h.authentication_data_block_size = round_to_multiple(
        alg.hash_num_bytes + alg.signature_num_bytes, 64)
    h.algorithm_type = alg.algorithm_type
    h.hash_offset = 0
    h.hash_size = alg.hash_num_bytes
    # Signature offset and size - it's stored right after the hash
    # (in Authentication data block).
    h.signature_offset = alg.hash_num_bytes
    h.signature_size = alg.signature_num_bytes

    h.rollback_index = rollback_index
    h.flags = flags

    # Generate Header data block.
    header_data_blob = h

    # Generate Auxiliary data block.
    aux_data_blob = bytearray()
    aux_data_blob.extend(encoded_descriptors)
    aux_data_blob.extend(encoded_key)
    aux_data_blob.extend(pkmd_blob)
    padding_bytes = h.auxiliary_data_block_size - len(aux_data_blob)
    aux_data_blob.extend(b'\0' * padding_bytes)

    # Calculate the hash.
    binary_hash = bytearray()
    binary_signature = bytearray()
    if algorithm_name != 'NONE':
        ha = hashlib.new(alg.hash_name)
        ha.update(header_data_blob.encode())
        ha.update(aux_data_blob)
        binary_hash.extend(ha.digest())

        # Calculate the signature.
        padding_and_hash = bytearray(alg.padding) + binary_hash
        binary_signature.extend(raw_sign(signing_helper,
                                         signing_helper_with_files,
                                         algorithm_name,
                                         alg.signature_num_bytes, key_path,
                                         padding_and_hash))

    # Generate Authentication data block.
    auth_data_blob = bytearray()
    auth_data_blob.extend(binary_hash)
    auth_data_blob.extend(binary_signature)
    padding_bytes = h.authentication_data_block_size - len(auth_data_blob)
    auth_data_blob.extend(b'\0' * padding_bytes)

    return header_data_blob.encode() + auth_data_blob + aux_data_blob


def add_hash_footer(image_filename, partition_size, partition_name,
                      hash_algorithm, salt, chain_partitions, algorithm_name,
                      key_path,
                      public_key_metadata_path, rollback_index, flags, props,
                      props_from_file, kernel_cmdlines,
                      setup_rootfs_from_kernel,
                      include_descriptors_from_image, calc_max_image_size,
                      signing_helper, signing_helper_with_files,
                      release_string, append_to_release_string,
                      output_vbmeta_image, do_not_append_vbmeta_image,
                      print_required_libavb_version, use_persistent_digest,
                      do_not_use_ab):
    """Implementation of the add_hash_footer on unsparse images.

    Arguments:
      image_filename: File to add the footer to.
      partition_size: Size of partition.
      partition_name: Name of partition (without A/B suffix).
      hash_algorithm: Hash algorithm to use.
      salt: Salt to use as a hexadecimal string or None to use /dev/urandom.
      chain_partitions: List of partitions to chain.
      algorithm_name: Name of algorithm to use.
      key_path: Path to key to use or None.
      public_key_metadata_path: Path to public key metadata or None.
      rollback_index: Rollback index.
      flags: Flags value to use in the image.
      props: Properties to insert (List of strings of the form 'key:value').
      props_from_file: Properties to insert (List of strings 'key:<path>').
      kernel_cmdlines: Kernel cmdlines to insert (list of strings).
      setup_rootfs_from_kernel: None or file to generate
        dm-verity kernel cmdline from.
      include_descriptors_from_image: List of file objects for which
        to insert descriptors from.
      calc_max_image_size: Don't store the footer - instead calculate the
        maximum image size leaving enough room for metadata with the
        given |partition_size|.
      signing_helper: Program which signs a hash and return signature.
      signing_helper_with_files: Same as signing_helper but uses files instead.
      release_string: None or avbtool release string.
      append_to_release_string: None or string to append.
      output_vbmeta_image: If not None, also write vbmeta struct to this file.
      do_not_append_vbmeta_image: If True, don't append vbmeta struct.
      print_required_libavb_version: True to only print required libavb version.
      use_persistent_digest: Use a persistent digest on device.
      do_not_use_ab: This partition does not use A/B.

    Raises:
      AvbError: If an argument is incorrect.
    """

    required_libavb_version_minor = 0
    if use_persistent_digest or do_not_use_ab:
      required_libavb_version_minor = 1

    # If we're asked to calculate minimum required libavb version, we're done.
    if print_required_libavb_version:
      print(('1.{}'.format(required_libavb_version_minor)))
      return

    # First, calculate the maximum image size such that an image
    # this size + metadata (footer + vbmeta struct) fits in
    # |partition_size|.
    max_metadata_size = MAX_VBMETA_SIZE + MAX_FOOTER_SIZE
    if partition_size < max_metadata_size:
      raise AvbError('Parition size of {} is too small. '
                     'Needs to be at least {}'.format(
                         partition_size, max_metadata_size))
    max_image_size = partition_size - max_metadata_size

    # If we're asked to only calculate the maximum image size, we're done.
    if calc_max_image_size:
      print(('{}'.format(max_image_size)))
      return

    image = ImageHandler(image_filename)

    if partition_size % image.block_size != 0:
      raise AvbError('Partition size of {} is not a multiple of the image '
                     'block size {}.'.format(partition_size,
                                             image.block_size))

    # If there's already a footer, truncate the image to its original
    # size. This way 'avbtool add_hash_footer' is idempotent (modulo
    # salts).
    if image.image_size >= AvbFooter.SIZE:
      image.seek(image.image_size - AvbFooter.SIZE)
      try:
        footer = AvbFooter(image.read(AvbFooter.SIZE))
        # Existing footer found. Just truncate.
        original_image_size = footer.original_image_size
        image.truncate(footer.original_image_size)
      except (LookupError, struct.error):
        original_image_size = image.image_size
    else:
      # Image size is too small to possibly contain a footer.
      original_image_size = image.image_size

    # If anything goes wrong from here-on, restore the image back to
    # its original size.
    try:
      # If image size exceeds the maximum image size, fail.
      if image.image_size > max_image_size:
        raise AvbError('Image size of {} exceeds maximum image '
                       'size of {} in order to fit in a partition '
                       'size of {}.'.format(image.image_size, max_image_size,
                                            partition_size))

      digest_size = len(hashlib.new(name=hash_algorithm).digest())
      if salt:
        salt = hex(salt)
      else:
        if salt is None and not use_persistent_digest:
          # If salt is not explicitly specified, choose a hash that's the same
          # size as the hash size. Don't populate a random salt if this
          # descriptor is being created to use a persistent digest on device.
          hash_size = digest_size
          salt = open('/dev/urandom','rb').read(hash_size)
        else:
          salt = ''

      hasher = hashlib.new(name=hash_algorithm, string=salt)
      # TODO(zeuthen): might want to read this in chunks to avoid
      # memory pressure, then again, this is only supposed to be used
      # on kernel/initramfs partitions. Possible optimization.
      image.seek(0)
      hasher.update(image.read(image.image_size))
      digest = hasher.digest()

      h_desc = AvbHashDescriptor()
      h_desc.image_size = image.image_size
      h_desc.hash_algorithm = bytes(hash_algorithm,'utf-8')
      h_desc.partition_name = bytes(partition_name,'utf-8')
      h_desc.salt = salt
      h_desc.flags = 0
      if do_not_use_ab:
        h_desc.flags |= 1  # AVB_HASH_DESCRIPTOR_FLAGS_DO_NOT_USE_AB
      if not use_persistent_digest:
        h_desc.digest = digest

      # Generate the VBMeta footer.
      ht_desc_to_setup = None
      vbmeta_blob = _generate_vbmeta_blob(
          algorithm_name, key_path, public_key_metadata_path, [h_desc],
          chain_partitions, rollback_index, flags, props, props_from_file,
          kernel_cmdlines, setup_rootfs_from_kernel, ht_desc_to_setup,
          include_descriptors_from_image, signing_helper,
          signing_helper_with_files, release_string,
          append_to_release_string, required_libavb_version_minor)

      # Write vbmeta blob, if requested.
      if output_vbmeta_image:
        with open(output_vbmeta_image,'wb') as wf:
            wf.write(vbmeta_blob)

      # Append vbmeta blob and footer, unless requested not to.
      if not do_not_append_vbmeta_image:
        # If the image isn't sparse, its size might not be a multiple of
        # the block size. This will screw up padding later so just grow it.
        if image.image_size % image.block_size != 0:
          assert not image.is_sparse
          padding_needed = image.block_size - (
              image.image_size % image.block_size)
          image.truncate(image.image_size + padding_needed)

        # The append_raw() method requires content with size being a
        # multiple of |block_size| so add padding as needed. Also record
        # where this is written to since we'll need to put that in the
        # footer.
        vbmeta_offset = image.image_size
        padding_needed = (
            round_to_multiple(len(vbmeta_blob), image.block_size) -
            len(vbmeta_blob))
        vbmeta_blob_with_padding = vbmeta_blob + b'\0' * padding_needed

        image.append_raw(vbmeta_blob_with_padding)
        vbmeta_end_offset = vbmeta_offset + len(vbmeta_blob_with_padding)

        # Now insert a DONT_CARE chunk with enough bytes such that the
        # final Footer block is at the end of partition_size..
        image.append_dont_care(partition_size - vbmeta_end_offset -
                               1*image.block_size)

        # Generate the Footer that tells where the VBMeta footer
        # is. Also put enough padding in the front of the footer since
        # we'll write out an entire block.
        footer = AvbFooter()
        footer.original_image_size = original_image_size
        footer.vbmeta_offset = vbmeta_offset
        footer.vbmeta_size = len(vbmeta_blob)
        footer_blob = footer
        footer_blob_with_padding = (b'\0'*(image.block_size - AvbFooter.SIZE) +
                                    footer_blob.encode())
        image.append_raw(footer_blob_with_padding)


    except Exception as e:
      print(e)
      # Truncate back to original size, then re-raise
      image.truncate(original_image_size)
      raise

class AvbError(Exception):
  """Application-specific errors.

  These errors represent issues for which a stack-trace should not be
  presented.

  Attributes:
    message: Error message.
  """

  def __init__(self, message):
    Exception.__init__(self, message)

class AvbFooter(object):
  """A class for parsing and writing footers.
  Footers are stored at the end of partitions and point to where the
  AvbVBMeta blob is located. They also contain the original size of
  the image before AVB information was added.
  Attributes:
    magic: Magic for identifying the footer, see |MAGIC|.
    version_major: The major version of avbtool that wrote the footer.
    version_minor: The minor version of avbtool that wrote the footer.
    original_image_size: Original image size.
    vbmeta_offset: Offset of where the AvbVBMeta blob is stored.
    vbmeta_size: Size of the AvbVBMeta blob.
  """
  MAGIC = b'AVBf'
  SIZE = 64
  RESERVED = 28
  FOOTER_VERSION_MAJOR = AVB_FOOTER_VERSION_MAJOR
  FOOTER_VERSION_MINOR = AVB_FOOTER_VERSION_MINOR
  FORMAT_STRING = ('!4s2L'  # magic, 2 x version.
                   'Q'  # Original image size.
                   'Q'  # Offset of VBMeta blob.
                   'Q' +  # Size of VBMeta blob.
                   str(RESERVED) + 'x')  # padding for reserved bytes

  def __init__(self, data=None):
    """Initializes a new footer object.
    Arguments:
      data: If not None, must be a bytearray of size 4096.
    Raises:
      LookupError: If the given footer is malformed.
      struct.error: If the given data has no footer.
    """
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE
    if data:
      (self.magic, self.version_major, self.version_minor,
       self.original_image_size, self.vbmeta_offset,
       self.vbmeta_size) = struct.unpack(self.FORMAT_STRING, data)
      if self.magic != self.MAGIC:
        raise LookupError('Given data does not look like a AVB footer.')
    else:
      self.magic = self.MAGIC
      self.version_major = self.FOOTER_VERSION_MAJOR
      self.version_minor = self.FOOTER_VERSION_MINOR
      self.original_image_size = 0
      self.vbmeta_offset = 0
      self.vbmeta_size = 0

  def encode(self):
    """Gets a string representing the binary encoding of the footer.
    Returns:
      A bytearray() with a binary representation of the footer.
    """
    return struct.pack(self.FORMAT_STRING, self.magic, self.version_major,
                       self.version_minor, self.original_image_size,
                       self.vbmeta_offset, self.vbmeta_size)

class ImageChunk(object):
  """Data structure used for representing chunks in Android sparse files.
  Attributes:
    chunk_type: One of TYPE_RAW, TYPE_FILL, or TYPE_DONT_CARE.
    chunk_offset: Offset in the sparse file where this chunk begins.
    output_offset: Offset in de-sparsified file where output begins.
    output_size: Number of bytes in output.
    input_offset: Offset in sparse file for data if TYPE_RAW otherwise None.
    fill_data: Blob with data to fill if TYPE_FILL otherwise None.
  """
  FORMAT = '<2H2I'
  TYPE_RAW = 0xcac1
  TYPE_FILL = 0xcac2
  TYPE_DONT_CARE = 0xcac3
  TYPE_CRC32 = 0xcac4
  def __init__(self, chunk_type, chunk_offset, output_offset, output_size,
               input_offset, fill_data):
    """Initializes an ImageChunk object.
    Arguments:
      chunk_type: One of TYPE_RAW, TYPE_FILL, or TYPE_DONT_CARE.
      chunk_offset: Offset in the sparse file where this chunk begins.
      output_offset: Offset in de-sparsified file.
      output_size: Number of bytes in output.
      input_offset: Offset in sparse file if TYPE_RAW otherwise None.
      fill_data: Blob with data to fill if TYPE_FILL otherwise None.
    Raises:
      ValueError: If data is not well-formed.
    """
    self.chunk_type = chunk_type
    self.chunk_offset = chunk_offset
    self.output_offset = output_offset
    self.output_size = output_size
    self.input_offset = input_offset
    self.fill_data = fill_data
    # Check invariants.
    if self.chunk_type == self.TYPE_RAW:
      if self.fill_data is not None:
        raise ValueError('RAW chunk cannot have fill_data set.')
      if not self.input_offset:
        raise ValueError('RAW chunk must have input_offset set.')
    elif self.chunk_type == self.TYPE_FILL:
      if self.fill_data is None:
        raise ValueError('FILL chunk must have fill_data set.')
      if self.input_offset:
        raise ValueError('FILL chunk cannot have input_offset set.')
    elif self.chunk_type == self.TYPE_DONT_CARE:
      if self.fill_data is not None:
        raise ValueError('DONT_CARE chunk cannot have fill_data set.')
      if self.input_offset:
        raise ValueError('DONT_CARE chunk cannot have input_offset set.')
    else:
      raise ValueError('Invalid chunk type')

class ImageHandler(object):
  """Abstraction for image I/O with support for Android sparse images.
  This class provides an interface for working with image files that
  may be using the Android Sparse Image format. When an instance is
  constructed, we test whether it's an Android sparse file. If so,
  operations will be on the sparse file by interpreting the sparse
  format, otherwise they will be directly on the file. Either way the
  operations do the same.
  For reading, this interface mimics a file object - it has seek(),
  tell(), and read() methods. For writing, only truncation
  (truncate()) and appending is supported (append_raw() and
  append_dont_care()). Additionally, data can only be written in units
  of the block size.
  Attributes:
    is_sparse: Whether the file being operated on is sparse.
    block_size: The block size, typically 4096.
    image_size: The size of the unsparsified file.
  """
  # See system/core/libsparse/sparse_format.h for details.
  MAGIC = 0xed26ff3a
  HEADER_FORMAT = '<I4H4I'
  # These are formats and offset of just the |total_chunks| and
  # |total_blocks| fields.
  NUM_CHUNKS_AND_BLOCKS_FORMAT = '<II'
  NUM_CHUNKS_AND_BLOCKS_OFFSET = 16
  def __init__(self, image_filename):
    """Initializes an image handler.
    Arguments:
      image_filename: The name of the file to operate on.
    Raises:
      ValueError: If data in the file is invalid.
    """
    self._image_filename = image_filename
    self._read_header()
  def _read_header(self):
    """Initializes internal data structures used for reading file.
    This may be called multiple times and is typically called after
    modifying the file (e.g. appending, truncation).
    Raises:
      ValueError: If data in the file is invalid.
    """
    self.is_sparse = False
    self.block_size = 4096
    self._file_pos = 0
    self._image = open(self._image_filename, 'r+b')
    self._image.seek(0, os.SEEK_END)
    self.image_size = self._image.tell()
    self._image.seek(0, os.SEEK_SET)
    header_bin = self._image.read(struct.calcsize(self.HEADER_FORMAT))
    (magic, major_version, minor_version, file_hdr_sz, chunk_hdr_sz,
     block_size, self._num_total_blocks, self._num_total_chunks,
     _) = struct.unpack(self.HEADER_FORMAT, header_bin)
    if magic != self.MAGIC:
      # Not a sparse image, our job here is done.
      return
    if not (major_version == 1 and minor_version == 0):
      raise ValueError('Encountered sparse image format version {}.{} but '
                       'only 1.0 is supported'.format(major_version,
                                                      minor_version))
    if file_hdr_sz != struct.calcsize(self.HEADER_FORMAT):
      raise ValueError('Unexpected file_hdr_sz value {}.'.
                       format(file_hdr_sz))
    if chunk_hdr_sz != struct.calcsize(ImageChunk.FORMAT):
      raise ValueError('Unexpected chunk_hdr_sz value {}.'.
                       format(chunk_hdr_sz))
    self.block_size = block_size
    # Build an list of chunks by parsing the file.
    self._chunks = []
    # Find the smallest offset where only "Don't care" chunks
    # follow. This will be the size of the content in the sparse
    # image.
    offset = 0
    output_offset = 0
    for _ in range(1, self._num_total_chunks + 1):
      chunk_offset = self._image.tell()
      header_bin = self._image.read(struct.calcsize(ImageChunk.FORMAT))
      (chunk_type, _, chunk_sz, total_sz) = struct.unpack(ImageChunk.FORMAT,
                                                          header_bin)
      data_sz = total_sz - struct.calcsize(ImageChunk.FORMAT)
      if chunk_type == ImageChunk.TYPE_RAW:
        if data_sz != (chunk_sz * self.block_size):
          raise ValueError('Raw chunk input size ({}) does not match output '
                           'size ({})'.
                           format(data_sz, chunk_sz*self.block_size))
        self._chunks.append(ImageChunk(ImageChunk.TYPE_RAW,
                                       chunk_offset,
                                       output_offset,
                                       chunk_sz*self.block_size,
                                       self._image.tell(),
                                       None))
        self._image.read(data_sz)
      elif chunk_type == ImageChunk.TYPE_FILL:
        if data_sz != 4:
          raise ValueError('Fill chunk should have 4 bytes of fill, but this '
                           'has {}'.format(data_sz))
        fill_data = self._image.read(4)
        self._chunks.append(ImageChunk(ImageChunk.TYPE_FILL,
                                       chunk_offset,
                                       output_offset,
                                       chunk_sz*self.block_size,
                                       None,
                                       fill_data))
      elif chunk_type == ImageChunk.TYPE_DONT_CARE:
        if data_sz != 0:
          raise ValueError('Don\'t care chunk input size is non-zero ({})'.
                           format(data_sz))
        self._chunks.append(ImageChunk(ImageChunk.TYPE_DONT_CARE,
                                       chunk_offset,
                                       output_offset,
                                       chunk_sz*self.block_size,
                                       None,
                                       None))
      elif chunk_type == ImageChunk.TYPE_CRC32:
        if data_sz != 4:
          raise ValueError('CRC32 chunk should have 4 bytes of CRC, but '
                           'this has {}'.format(data_sz))
        self._image.read(4)
      else:
        raise ValueError('Unknown chunk type {}'.format(chunk_type))
      offset += chunk_sz
      output_offset += chunk_sz*self.block_size
    # Record where sparse data end.
    self._sparse_end = self._image.tell()
    # Now that we've traversed all chunks, sanity check.
    if self._num_total_blocks != offset:
      raise ValueError('The header said we should have {} output blocks, '
                       'but we saw {}'.format(self._num_total_blocks, offset))
    junk_len = len(self._image.read())
    if junk_len > 0:
      raise ValueError('There were {} bytes of extra data at the end of the '
                       'file.'.format(junk_len))
    # Assign |image_size|.
    self.image_size = output_offset
    # This is used when bisecting in read() to find the initial slice.
    self._chunk_output_offsets = [i.output_offset for i in self._chunks]
    self.is_sparse = True

  def _update_chunks_and_blocks(self):
    """Helper function to update the image header.
    The the |total_chunks| and |total_blocks| fields in the header
    will be set to value of the |_num_total_blocks| and
    |_num_total_chunks| attributes.
    """
    self._image.seek(self.NUM_CHUNKS_AND_BLOCKS_OFFSET, os.SEEK_SET)
    self._image.write(struct.pack(self.NUM_CHUNKS_AND_BLOCKS_FORMAT,
                                  self._num_total_blocks,
                                  self._num_total_chunks))

  def append_dont_care(self, num_bytes):
    """Appends a DONT_CARE chunk to the sparse file.
    The given number of bytes must be a multiple of the block size.
    Arguments:
      num_bytes: Size in number of bytes of the DONT_CARE chunk.
    """
    assert num_bytes % self.block_size == 0
    if not self.is_sparse:
      self._image.seek(0, os.SEEK_END)
      # This is more efficient that writing NUL bytes since it'll add
      # a hole on file systems that support sparse files (native
      # sparse, not Android sparse).
      self._image.truncate(self._image.tell() + num_bytes)
      self._read_header()
      return
    self._num_total_chunks += 1
    self._num_total_blocks += num_bytes / self.block_size
    self._update_chunks_and_blocks()
    self._image.seek(self._sparse_end, os.SEEK_SET)
    self._image.write(struct.pack(ImageChunk.FORMAT,
                                  ImageChunk.TYPE_DONT_CARE,
                                  0,  # Reserved
                                  num_bytes / self.block_size,
                                  struct.calcsize(ImageChunk.FORMAT)))
    self._read_header()

  def append_raw(self, data):
    """Appends a RAW chunk to the sparse file.
    The length of the given data must be a multiple of the block size.
    Arguments:
      data: Data to append.
    """
    assert len(data) % self.block_size == 0
    if not self.is_sparse:
      self._image.seek(0, os.SEEK_END)
      self._image.write(data)
      self._read_header()
      return
    self._num_total_chunks += 1
    self._num_total_blocks += len(data) / self.block_size
    self._update_chunks_and_blocks()
    self._image.seek(self._sparse_end, os.SEEK_SET)
    self._image.write(struct.pack(ImageChunk.FORMAT,
                                  ImageChunk.TYPE_RAW,
                                  0,  # Reserved
                                  len(data) / self.block_size,
                                  len(data) +
                                  struct.calcsize(ImageChunk.FORMAT)))
    self._image.write(data)
    self._read_header()

  def append_fill(self, fill_data, size):
    """Appends a fill chunk to the sparse file.
    The total length of the fill data must be a multiple of the block size.
    Arguments:
      fill_data: Fill data to append - must be four bytes.
      size: Number of chunk - must be a multiple of four and the block size.
    """
    assert len(fill_data) == 4
    assert size % 4 == 0
    assert size % self.block_size == 0
    if not self.is_sparse:
      self._image.seek(0, os.SEEK_END)
      self._image.write(fill_data * (size/4))
      self._read_header()
      return
    self._num_total_chunks += 1
    self._num_total_blocks += size / self.block_size
    self._update_chunks_and_blocks()
    self._image.seek(self._sparse_end, os.SEEK_SET)
    self._image.write(struct.pack(ImageChunk.FORMAT,
                                  ImageChunk.TYPE_FILL,
                                  0,  # Reserved
                                  size / self.block_size,
                                  4 + struct.calcsize(ImageChunk.FORMAT)))
    self._image.write(fill_data)
    self._read_header()

  def seek(self, offset):
    """Sets the cursor position for reading from unsparsified file.
    Arguments:
      offset: Offset to seek to from the beginning of the file.
    """
    if offset < 0:
      raise RuntimeError("Seeking with negative offset: %d" % offset)
    self._file_pos = offset

  def read(self, size):
    """Reads data from the unsparsified file.
    This method may return fewer than |size| bytes of data if the end
    of the file was encountered.
    The file cursor for reading is advanced by the number of bytes
    read.
    Arguments:
      size: Number of bytes to read.
    Returns:
      The data.
    """
    if not self.is_sparse:
      self._image.seek(self._file_pos)
      data = self._image.read(size)
      self._file_pos += len(data)
      return data
    # Iterate over all chunks.
    chunk_idx = bisect.bisect_right(self._chunk_output_offsets,
                                    self._file_pos) - 1
    data = bytearray()
    to_go = size
    while to_go > 0:
      chunk = self._chunks[chunk_idx]
      chunk_pos_offset = self._file_pos - chunk.output_offset
      chunk_pos_to_go = min(chunk.output_size - chunk_pos_offset, to_go)
      if chunk.chunk_type == ImageChunk.TYPE_RAW:
        self._image.seek(chunk.input_offset + chunk_pos_offset)
        data.extend(self._image.read(chunk_pos_to_go))
      elif chunk.chunk_type == ImageChunk.TYPE_FILL:
        all_data = chunk.fill_data*(chunk_pos_to_go/len(chunk.fill_data) + 2)
        offset_mod = chunk_pos_offset % len(chunk.fill_data)
        data.extend(all_data[offset_mod:(offset_mod + chunk_pos_to_go)])
      else:
        assert chunk.chunk_type == ImageChunk.TYPE_DONT_CARE
        data.extend(b'\0' * chunk_pos_to_go)
      to_go -= chunk_pos_to_go
      self._file_pos += chunk_pos_to_go
      chunk_idx += 1
      # Generate partial read in case of EOF.
      if chunk_idx >= len(self._chunks):
        break
    return data

  def tell(self):
    """Returns the file cursor position for reading from unsparsified file.
    Returns:
      The file cursor position for reading.
    """
    return self._file_pos

  def truncate(self, size):
    """Truncates the unsparsified file.
    Arguments:
      size: Desired size of unsparsified file.
    Raises:
      ValueError: If desired size isn't a multiple of the block size.
    """
    if not self.is_sparse:
      self._image.truncate(size)
      self._read_header()
      return
    if size % self.block_size != 0:
      raise ValueError('Cannot truncate to a size which is not a multiple '
                       'of the block size')
    if size == self.image_size:
      # Trivial where there's nothing to do.
      return
    elif size < self.image_size:
      chunk_idx = bisect.bisect_right(self._chunk_output_offsets, size) - 1
      chunk = self._chunks[chunk_idx]
      if chunk.output_offset != size:
        # Truncation in the middle of a trunk - need to keep the chunk
        # and modify it.
        chunk_idx_for_update = chunk_idx + 1
        num_to_keep = size - chunk.output_offset
        assert num_to_keep % self.block_size == 0
        if chunk.chunk_type == ImageChunk.TYPE_RAW:
          truncate_at = (chunk.chunk_offset +
                         struct.calcsize(ImageChunk.FORMAT) + num_to_keep)
          data_sz = num_to_keep
        elif chunk.chunk_type == ImageChunk.TYPE_FILL:
          truncate_at = (chunk.chunk_offset +
                         struct.calcsize(ImageChunk.FORMAT) + 4)
          data_sz = 4
        else:
          assert chunk.chunk_type == ImageChunk.TYPE_DONT_CARE
          truncate_at = chunk.chunk_offset + struct.calcsize(ImageChunk.FORMAT)
          data_sz = 0
        chunk_sz = num_to_keep/self.block_size
        total_sz = data_sz + struct.calcsize(ImageChunk.FORMAT)
        self._image.seek(chunk.chunk_offset)
        self._image.write(struct.pack(ImageChunk.FORMAT,
                                      chunk.chunk_type,
                                      0,  # Reserved
                                      chunk_sz,
                                      total_sz))
        chunk.output_size = num_to_keep
      else:
        # Truncation at trunk boundary.
        truncate_at = chunk.chunk_offset
        chunk_idx_for_update = chunk_idx
      self._num_total_chunks = chunk_idx_for_update
      self._num_total_blocks = 0
      for i in range(0, chunk_idx_for_update):
        self._num_total_blocks += self._chunks[i].output_size / self.block_size
      self._update_chunks_and_blocks()
      self._image.truncate(truncate_at)
      # We've modified the file so re-read all data.
      self._read_header()
    else:
      # Truncating to grow - just add a DONT_CARE section.
      self.append_dont_care(size - self.image_size)

def round_to_multiple(number, size):
  """Rounds a number up to nearest multiple of another number.
  Args:
    number: The number to round up.
    size: The multiple to round up to.
  Returns:
    If |number| is a multiple of |size|, returns |number|, otherwise
    returns |number| + |size|.
  """
  remainder = number % size
  if remainder == 0:
    return number
  return number + size - remainder


def round_to_pow2(number):
  """Rounds a number up to the next power of 2.
  Args:
    number: The number to round up.
  Returns:
    If |number| is already a power of 2 then |number| is
    returned. Otherwise the smallest power of 2 greater than |number|
    is returned.
  """
  return 2**((number - 1).bit_length())

class AvbVBMetaHeader(object):
  """A class for parsing and writing AVB vbmeta images.
  Attributes:
    The attributes correspond to the |AvbVBMetaHeader| struct
    defined in avb_vbmeta_header.h.
  """

  SIZE = 256

  # Keep in sync with |reserved0| and |reserved| field of
  # |AvbVBMetaImageHeader|.
  RESERVED0 = 4
  RESERVED = 80

  # Keep in sync with |AvbVBMetaImageHeader|.
  FORMAT_STRING = ('!4s2L'  # magic, 2 x version
                   '2Q'  # 2 x block size
                   'L'  # algorithm type
                   '2Q'  # offset, size (hash)
                   '2Q'  # offset, size (signature)
                   '2Q'  # offset, size (public key)
                   '2Q'  # offset, size (public key metadata)
                   '2Q'  # offset, size (descriptors)
                   'Q'  # rollback_index
                   'L' +  # flags
                   str(RESERVED0) + 'x' +  # padding for reserved bytes
                   '47sx' +  # NUL-terminated release string
                   str(RESERVED) + 'x')  # padding for reserved bytes

  def __init__(self, data=None):
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE

    if data:
      (self.magic, self.required_libavb_version_major,
       self.required_libavb_version_minor,
       self.authentication_data_block_size, self.auxiliary_data_block_size,
       self.algorithm_type, self.hash_offset, self.hash_size,
       self.signature_offset, self.signature_size, self.public_key_offset,
       self.public_key_size, self.public_key_metadata_offset,
       self.public_key_metadata_size, self.descriptors_offset,
       self.descriptors_size,
       self.rollback_index,
       self.flags,
       self.release_string) = struct.unpack(self.FORMAT_STRING, data)
    else:
      self.magic = b'AVB0'
      # Start by just requiring version 1.0. Code that adds features
      # in a future version can use bump_required_libavb_version_minor() to
      # bump the minor.
      self.required_libavb_version_major = AVB_VERSION_MAJOR
      self.required_libavb_version_minor = 0
      self.authentication_data_block_size = 0
      self.auxiliary_data_block_size = 0
      self.algorithm_type = 0
      self.hash_offset = 0
      self.hash_size = 0
      self.signature_offset = 0
      self.signature_size = 0
      self.public_key_offset = 0
      self.public_key_size = 0
      self.public_key_metadata_offset = 0
      self.public_key_metadata_size = 0
      self.descriptors_offset = 0
      self.descriptors_size = 0
      self.rollback_index = 0
      self.flags = 0
      self.release_string = get_release_string()

  def bump_required_libavb_version_minor(self, minor):
    """Function to bump required_libavb_version_minor.

    Call this when writing data that requires a specific libavb
    version to parse it.

    Arguments:
      minor: The minor version of libavb that has support for the feature.
    """
    self.required_libavb_version_minor = (
        max(self.required_libavb_version_minor, minor))

  def encode(self):
    return struct.pack(self.FORMAT_STRING, self.magic,
                       self.required_libavb_version_major,
                       self.required_libavb_version_minor,
                       self.authentication_data_block_size,
                       self.auxiliary_data_block_size, self.algorithm_type,
                       self.hash_offset, self.hash_size, self.signature_offset,
                       self.signature_size, self.public_key_offset,
                       self.public_key_size, self.public_key_metadata_offset,
                       self.public_key_metadata_size, self.descriptors_offset,
                       self.descriptors_size, self.rollback_index, self.flags,
                       self.release_string)

class AvbDescriptor(object):
  """Class for AVB descriptor.
  See the |AvbDescriptor| C struct for more information.
  Attributes:
    tag: The tag identifying what kind of descriptor this is.
    data: The data in the descriptor.
  """
  SIZE = 16
  FORMAT_STRING = ('!QQ')  # tag, num_bytes_following (descriptor header)

  def __init__(self, data):
    """Initializes a new property descriptor.
    Arguments:
      data: If not None, must be a bytearray().
    Raises:
      LookupError: If the given descriptor is malformed.
    """
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE
    if data:
      (self.tag, num_bytes_following) = (
          struct.unpack(self.FORMAT_STRING, data[0:self.SIZE]))
      self.data = data[self.SIZE:self.SIZE + num_bytes_following]
    else:
      self.tag = None
      self.data = None

  def print_desc(self, o):
    """Print the descriptor.
    Arguments:
      o: The object to write the output to.
    """
    o.write('    Unknown descriptor:\n')
    o.write('      Tag:  {}\n'.format(self.tag))
    if len(self.data) < 256:
      o.write('      Data: {} ({} bytes)\n'.format(
          repr(str(self.data)), len(self.data)))
    else:
      o.write('      Data: {} bytes\n'.format(len(self.data)))

  def encode(self):
    """Serializes the descriptor.
    Returns:
      A bytearray() with the descriptor data.
    """
    num_bytes_following = len(self.data)
    nbf_with_padding = round_to_multiple(num_bytes_following, 8)
    padding_size = nbf_with_padding - num_bytes_following
    desc = struct.pack(self.FORMAT_STRING, self.tag, nbf_with_padding)
    padding = struct.pack(str(padding_size) + 'x')
    ret = desc + self.data + padding
    return bytearray(ret)

  def verify(self, image_dir, image_ext, expected_chain_partitions_map):
    """Verifies contents of the descriptor - used in verify_image sub-command.
    Arguments:
      image_dir: The directory of the file being verified.
      image_ext: The extension of the file being verified (e.g. '.img').
      expected_chain_partitions_map: A map from partition name to the
        tuple (rollback_index_location, key_blob).
    Returns:
      True if the descriptor verifies, False otherwise.
    """
    # Nothing to do.
    return True

class AvbPropertyDescriptor(AvbDescriptor):
  """A class for property descriptors.
  See the |AvbPropertyDescriptor| C struct for more information.
  Attributes:
    key: The key.
    value: The key.
  """
  TAG = 0
  SIZE = 32
  FORMAT_STRING = ('!QQ'  # tag, num_bytes_following (descriptor header)
                   'Q'  # key size (bytes)
                   'Q')  # value size (bytes)

  def __init__(self, data=None):
    """Initializes a new property descriptor.
    Arguments:
      data: If not None, must be a bytearray of size |SIZE|.
    Raises:
      LookupError: If the given descriptor is malformed.
    """
    AvbDescriptor.__init__(self, None)
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE
    if data:
      (tag, num_bytes_following, key_size,
       value_size) = struct.unpack(self.FORMAT_STRING, data[0:self.SIZE])
      expected_size = round_to_multiple(
          self.SIZE - 16 + key_size + 1 + value_size + 1, 8)
      if tag != self.TAG or num_bytes_following != expected_size:
        raise LookupError('Given data does not look like a property '
                          'descriptor.')
      self.key = data[self.SIZE:(self.SIZE + key_size)]
      self.value = data[(self.SIZE + key_size + 1):(self.SIZE + key_size + 1 +
                                                    value_size)]
    else:
      self.key = b''
      self.value = b''

  def print_desc(self, o):
    """Print the descriptor.
    Arguments:
      o: The object to write the output to.
    """
    if len(self.value) < 256:
      o.write('    Prop: {} -> {}\n'.format(self.key, repr(str(self.value))))
    else:
      o.write('    Prop: {} -> ({} bytes)\n'.format(self.key, len(self.value)))

  def encode(self):
    """Serializes the descriptor.
    Returns:
      A bytearray() with the descriptor data.
    """
    num_bytes_following = self.SIZE + len(self.key) + len(self.value) + 2 - 16
    nbf_with_padding = round_to_multiple(num_bytes_following, 8)
    padding_size = nbf_with_padding - num_bytes_following
    desc = struct.pack(self.FORMAT_STRING, self.TAG, nbf_with_padding,
                       len(self.key), len(self.value))
    padding = struct.pack(str(padding_size) + 'x')
    ret = desc + self.key + b'\0' + self.value + b'\0' + padding
    return bytearray(ret)

  def verify(self, image_dir, image_ext, expected_chain_partitions_map):
    """Verifies contents of the descriptor - used in verify_image sub-command.
    Arguments:
      image_dir: The directory of the file being verified.
      image_ext: The extension of the file being verified (e.g. '.img').
      expected_chain_partitions_map: A map from partition name to the
        tuple (rollback_index_location, key_blob).
    Returns:
      True if the descriptor verifies, False otherwise.
    """
    # Nothing to do.
    return True

class AvbHashtreeDescriptor(AvbDescriptor):
  """A class for hashtree descriptors.
  See the |AvbHashtreeDescriptor| C struct for more information.
  Attributes:
    dm_verity_version: dm-verity version used.
    image_size: Size of the image, after rounding up to |block_size|.
    tree_offset: Offset of the hash tree in the file.
    tree_size: Size of the tree.
    data_block_size: Data block size
    hash_block_size: Hash block size
    fec_num_roots: Number of roots used for FEC (0 if FEC is not used).
    fec_offset: Offset of FEC data (0 if FEC is not used).
    fec_size: Size of FEC data (0 if FEC is not used).
    hash_algorithm: Hash algorithm used.
    partition_name: Partition name.
    salt: Salt used.
    root_digest: Root digest.
    flags: Descriptor flags (see avb_hashtree_descriptor.h).
  """
  TAG = 1
  RESERVED = 60
  SIZE = 120 + RESERVED
  FORMAT_STRING = ('!QQ'  # tag, num_bytes_following (descriptor header)
                   'L'  # dm-verity version used
                   'Q'  # image size (bytes)
                   'Q'  # tree offset (bytes)
                   'Q'  # tree size (bytes)
                   'L'  # data block size (bytes)
                   'L'  # hash block size (bytes)
                   'L'  # FEC number of roots
                   'Q'  # FEC offset (bytes)
                   'Q'  # FEC size (bytes)
                   '32s'  # hash algorithm used
                   'L'  # partition name (bytes)
                   'L'  # salt length (bytes)
                   'L'  # root digest length (bytes)
                   'L' +  # flags
                   str(RESERVED) + 's')  # reserved

  def __init__(self, data=None):
    """Initializes a new hashtree descriptor.
    Arguments:
      data: If not None, must be a bytearray of size |SIZE|.
    Raises:
      LookupError: If the given descriptor is malformed.
    """
    AvbDescriptor.__init__(self, None)
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE
    if data:
      (tag, num_bytes_following, self.dm_verity_version, self.image_size,
       self.tree_offset, self.tree_size, self.data_block_size,
       self.hash_block_size, self.fec_num_roots, self.fec_offset, self.fec_size,
       self.hash_algorithm, partition_name_len, salt_len,
       root_digest_len, self.flags, _) = struct.unpack(self.FORMAT_STRING,
                                                       data[0:self.SIZE])
      expected_size = round_to_multiple(
          self.SIZE - 16 + partition_name_len + salt_len + root_digest_len, 8)
      if tag != self.TAG or num_bytes_following != expected_size:
        raise LookupError('Given data does not look like a hashtree '
                          'descriptor.')
      # Nuke NUL-bytes at the end.
      self.hash_algorithm = bytes(self.hash_algorithm.split(b'\0', 1)[0]).decode('utf-8')
      o = 0
      self.partition_name = bytes(data[(self.SIZE + o):(self.SIZE + o +
                                                      partition_name_len)]).decode('utf-8')
      # Validate UTF-8 - decode() raises UnicodeDecodeError if not valid UTF-8.
      o += partition_name_len
      self.salt = data[(self.SIZE + o):(self.SIZE + o + salt_len)]
      o += salt_len
      self.root_digest = data[(self.SIZE + o):(self.SIZE + o + root_digest_len)]
      if root_digest_len != len(hashlib.new(name=self.hash_algorithm).digest()):
        if root_digest_len != 0:
          raise LookupError('root_digest_len doesn\'t match hash algorithm')
    else:
      self.dm_verity_version = 0
      self.image_size = 0
      self.tree_offset = 0
      self.tree_size = 0
      self.data_block_size = 0
      self.hash_block_size = 0
      self.fec_num_roots = 0
      self.fec_offset = 0
      self.fec_size = 0
      self.hash_algorithm = ''
      self.partition_name = ''
      self.salt = bytearray()
      self.root_digest = bytearray()
      self.flags = 0

  def print_desc(self, o):
    """Print the descriptor.
    Arguments:
      o: The object to write the output to.
    """
    o.write('    Hashtree descriptor:\n')
    o.write('      Version of dm-verity:  {}\n'.format(self.dm_verity_version))
    o.write('      Image Size:            {} bytes\n'.format(self.image_size))
    o.write('      Tree Offset:           {}\n'.format(self.tree_offset))
    o.write('      Tree Size:             {} bytes\n'.format(self.tree_size))
    o.write('      Data Block Size:       {} bytes\n'.format(
        self.data_block_size))
    o.write('      Hash Block Size:       {} bytes\n'.format(
        self.hash_block_size))
    o.write('      FEC num roots:         {}\n'.format(self.fec_num_roots))
    o.write('      FEC offset:            {}\n'.format(self.fec_offset))
    o.write('      FEC size:              {} bytes\n'.format(self.fec_size))
    o.write('      Hash Algorithm:        {}\n'.format(self.hash_algorithm))
    o.write('      Partition Name:        {}\n'.format(self.partition_name))
    o.write('      Salt:                  {}\n'.format(str(self.salt).encode(
        'hex')))
    o.write('      Root Digest:           {}\n'.format(str(
        self.root_digest).encode('hex')))
    o.write('      Flags:                 {}\n'.format(self.flags))

  def encode(self):
    """Serializes the descriptor.
    Returns:
      A bytearray() with the descriptor data.
    """
    encoded_name = self.partition_name.encode('utf-8')
    num_bytes_following = (self.SIZE + len(encoded_name) + len(self.salt) +
                           len(self.root_digest) - 16)
    nbf_with_padding = round_to_multiple(num_bytes_following, 8)
    padding_size = nbf_with_padding - num_bytes_following
    if type(self.hash_algorithm)==str:
        self.hash_algorithm=bytes(self.hash_algorithm,'utf-8')
    desc = struct.pack(self.FORMAT_STRING, self.TAG, nbf_with_padding,
                       self.dm_verity_version, self.image_size,
                       self.tree_offset, self.tree_size, self.data_block_size,
                       self.hash_block_size, self.fec_num_roots,
                       self.fec_offset, self.fec_size, self.hash_algorithm,
                       len(encoded_name), len(self.salt), len(self.root_digest),
                       self.flags, self.RESERVED*b'\0')
    padding = struct.pack(str(padding_size) + 'x')
    ret = desc + encoded_name + self.salt + self.root_digest + padding
    return bytearray(ret)

  def verify(self, image_dir, image_ext, expected_chain_partitions_map):
    """Verifies contents of the descriptor - used in verify_image sub-command.
    Arguments:
      image_dir: The directory of the file being verified.
      image_ext: The extension of the file being verified (e.g. '.img').
      expected_chain_partitions_map: A map from partition name to the
        tuple (rollback_index_location, key_blob).
    Returns:
      True if the descriptor verifies, False otherwise.
    """
    image_filename = os.path.join(image_dir, self.partition_name + image_ext)
    image = ImageHandler(image_filename)
    # Generate the hashtree and checks that it matches what's in the file.
    digest_size = len(hashlib.new(name=self.hash_algorithm).digest())
    digest_padding = round_to_pow2(digest_size) - digest_size
    (hash_level_offsets, tree_size) = calc_hash_level_offsets(
      self.image_size, self.data_block_size, digest_size + digest_padding)
    root_digest, hash_tree = generate_hash_tree(image, self.image_size,
                                                self.data_block_size,
                                                self.hash_algorithm, self.salt,
                                                digest_padding,
                                                hash_level_offsets,
                                                tree_size)
    # The root digest must match unless it is not embedded in the descriptor.
    if len(self.root_digest) != 0 and root_digest != self.root_digest:
      sys.stderr.write('hashtree of {} does not match descriptor\n'.
                       format(image_filename))
      return False
    # ... also check that the on-disk hashtree matches
    image.seek(self.tree_offset)
    hash_tree_ondisk = image.read(self.tree_size)
    if hash_tree != hash_tree_ondisk:
      sys.stderr.write('hashtree of {} contains invalid data\n'.
                       format(image_filename))
      return False
    # TODO: we could also verify that the FEC stored in the image is
    # correct but this a) currently requires the 'fec' binary; and b)
    # takes a long time; and c) is not strictly needed for
    # verification purposes as we've already verified the root hash.
    print ('{}: Successfully verified {} hashtree of {} for image of {} bytes'
           .format(self.partition_name, self.hash_algorithm, image_filename,
                   self.image_size))
    return True

class AvbHashDescriptor(AvbDescriptor):
  """A class for hash descriptors.
  See the |AvbHashDescriptor| C struct for more information.
  Attributes:
    image_size: Image size, in bytes.
    hash_algorithm: Hash algorithm used.
    partition_name: Partition name.
    salt: Salt used.
    digest: The hash value of salt and data combined.
    flags: The descriptor flags (see avb_hash_descriptor.h).
  """
  TAG = 2
  RESERVED = 60
  SIZE = 72 + RESERVED
  FORMAT_STRING = ('!QQ'  # tag, num_bytes_following (descriptor header)
                   'Q'  # image size (bytes)
                   '32s'  # hash algorithm used
                   'L'  # partition name (bytes)
                   'L'  # salt length (bytes)
                   'L'  # digest length (bytes)
                   'L' +  # flags
                   str(RESERVED) + 's')  # reserved

  def __init__(self, data=None):
    """Initializes a new hash descriptor.
    Arguments:
      data: If not None, must be a bytearray of size |SIZE|.
    Raises:
      LookupError: If the given descriptor is malformed.
    """
    AvbDescriptor.__init__(self, None)
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE
    if data:
      (tag, num_bytes_following, self.image_size, self.hash_algorithm,
       partition_name_len, salt_len,
       digest_len, self.flags, _) = struct.unpack(self.FORMAT_STRING,
                                                  data[0:self.SIZE])
      expected_size = round_to_multiple(
          self.SIZE - 16 + partition_name_len + salt_len + digest_len, 8)
      if tag != self.TAG or num_bytes_following != expected_size:
        raise LookupError('Given data does not look like a hash ' 'descriptor.')
      # Nuke NUL-bytes at the end.
      self.hash_algorithm = self.hash_algorithm.split(b'\0', 1)[0].decode('UTF-8')
      o = 0
      self.partition_name = bytes(data[(self.SIZE + o):(self.SIZE + o +
                                                      partition_name_len)]).decode('utf-8')

      # Validate UTF-8 - decode() raises UnicodeDecodeError if not valid UTF-8.
      o += partition_name_len
      self.salt = data[(self.SIZE + o):(self.SIZE + o + salt_len)]
      o += salt_len
      self.digest = data[(self.SIZE + o):(self.SIZE + o + digest_len)]
      if digest_len != len(hashlib.new(name=self.hash_algorithm).digest()):
        if digest_len != 0:
          raise LookupError('digest_len doesn\'t match hash algorithm')
    else:
      self.image_size = 0
      self.hash_algorithm = ''
      self.partition_name = ''
      self.salt = bytearray()
      self.digest = bytearray()
      self.flags = 0

  def print_desc(self, o):
    """Print the descriptor.
    Arguments:
      o: The object to write the output to.
    """
    o.write('    Hash descriptor:\n')
    o.write('      Image Size:            {} bytes\n'.format(self.image_size))
    o.write('      Hash Algorithm:        {}\n'.format(self.hash_algorithm))
    o.write('      Partition Name:        {}\n'.format(self.partition_name))
    o.write('      Salt:                  {}\n'.format(str(self.salt).encode(
        'hex')))
    o.write('      Digest:                {}\n'.format(str(self.digest).encode(
        'hex')))
    o.write('      Flags:                 {}\n'.format(self.flags))

  def encode(self):
    """Serializes the descriptor.
    Returns:
      A bytearray() with the descriptor data.
    """
    encoded_name = self.partition_name
    num_bytes_following = (
        self.SIZE + len(encoded_name) + len(self.salt) + len(self.digest) - 16)
    nbf_with_padding = round_to_multiple(num_bytes_following, 8)
    padding_size = nbf_with_padding - num_bytes_following
    if type(self.hash_algorithm)==str:
        self.hash_algorithm=bytes(self.hash_algorithm,'utf-8')
    if type(encoded_name)==str:
        encoded_name=bytes(encoded_name,'utf-8')
    desc = struct.pack(self.FORMAT_STRING, self.TAG, nbf_with_padding,
                       self.image_size, self.hash_algorithm, len(encoded_name),
                       len(self.salt), len(self.digest), self.flags,
                       self.RESERVED*b'\0')
    padding = struct.pack(str(padding_size) + 'x')
    ret = desc + encoded_name + self.salt + self.digest + padding
    return bytearray(ret)

  def verify(self, image_dir, image_ext, expected_chain_partitions_map):
    """Verifies contents of the descriptor - used in verify_image sub-command.
    Arguments:
      image_dir: The directory of the file being verified.
      image_ext: The extension of the file being verified (e.g. '.img').
      expected_chain_partitions_map: A map from partition name to the
        tuple (rollback_index_location, key_blob).
    Returns:
      True if the descriptor verifies, False otherwise.
    """
    image_filename = os.path.join(image_dir, self.partition_name + image_ext)
    image = ImageHandler(image_filename)
    data = image.read(self.image_size)
    ha = hashlib.new(self.hash_algorithm)
    ha.update(self.salt)
    ha.update(data)
    digest = ha.digest()
    # The digest must match unless there is no digest in the descriptor.
    if len(self.digest) != 0 and digest != self.digest:
      sys.stderr.write('{} digest of {} does not match digest in descriptor\n'.
                       format(self.hash_algorithm, image_filename))
      return False
    print ('{}: Successfully verified {} hash of {} for image of {} bytes'
           .format(self.partition_name, self.hash_algorithm, image_filename,
                   self.image_size))
    return True

class AvbKernelCmdlineDescriptor(AvbDescriptor):
  """A class for kernel command-line descriptors.
  See the |AvbKernelCmdlineDescriptor| C struct for more information.
  Attributes:
    flags: Flags.
    kernel_cmdline: The kernel command-line.
  """
  TAG = 3
  SIZE = 24
  FORMAT_STRING = ('!QQ'  # tag, num_bytes_following (descriptor header)
                   'L'  # flags
                   'L')  # cmdline length (bytes)
  FLAGS_USE_ONLY_IF_HASHTREE_NOT_DISABLED = (1 << 0)
  FLAGS_USE_ONLY_IF_HASHTREE_DISABLED = (1 << 1)

  def __init__(self, data=None):
    """Initializes a new kernel cmdline descriptor.
    Arguments:
      data: If not None, must be a bytearray of size |SIZE|.
    Raises:
      LookupError: If the given descriptor is malformed.
    """
    AvbDescriptor.__init__(self, None)
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE
    if data:
      (tag, num_bytes_following, self.flags, kernel_cmdline_length) = (
          struct.unpack(self.FORMAT_STRING, data[0:self.SIZE]))
      expected_size = round_to_multiple(self.SIZE - 16 + kernel_cmdline_length,
                                        8)
      if tag != self.TAG or num_bytes_following != expected_size:
        raise LookupError('Given data does not look like a kernel cmdline '
                          'descriptor.')
      # Nuke NUL-bytes at the end.
      self.kernel_cmdline = bytes(data[self.SIZE:(self.SIZE +
                                                kernel_cmdline_length)])
      # Validate UTF-8 - decode() raises UnicodeDecodeError if not valid UTF-8.
      self.kernel_cmdline.decode('utf-8')
    else:
      self.flags = 0
      self.kernel_cmdline = ''

  def print_desc(self, o):
    """Print the descriptor.
    Arguments:
      o: The object to write the output to.
    """
    o.write('    Kernel Cmdline descriptor:\n')
    o.write('      Flags:                 {}\n'.format(self.flags))
    o.write('      Kernel Cmdline:        {}\n'.format(repr(
        self.kernel_cmdline)))

  def encode(self):
    """Serializes the descriptor.
    Returns:
      A bytearray() with the descriptor data.
    """
    encoded_str = self.kernel_cmdline.encode('utf-8')
    num_bytes_following = (self.SIZE + len(encoded_str) - 16)
    nbf_with_padding = round_to_multiple(num_bytes_following, 8)
    padding_size = nbf_with_padding - num_bytes_following
    desc = struct.pack(self.FORMAT_STRING, self.TAG, nbf_with_padding,
                       self.flags, len(encoded_str))
    padding = struct.pack(str(padding_size) + 'x')
    ret = desc + encoded_str + padding
    return bytearray(ret)

  def verify(self, image_dir, image_ext, expected_chain_partitions_map):
    """Verifies contents of the descriptor - used in verify_image sub-command.
    Arguments:
      image_dir: The directory of the file being verified.
      image_ext: The extension of the file being verified (e.g. '.img').
      expected_chain_partitions_map: A map from partition name to the
        tuple (rollback_index_location, key_blob).
    Returns:
      True if the descriptor verifies, False otherwise.
    """
    # Nothing to verify.
    return True

class AvbChainPartitionDescriptor(AvbDescriptor):
  """A class for chained partition descriptors.
  See the |AvbChainPartitionDescriptor| C struct for more information.
  Attributes:
    rollback_index_location: The rollback index location to use.
    partition_name: Partition name.
    public_key: Bytes for the public key.
  """
  TAG = 4
  RESERVED = 64
  SIZE = 28 + RESERVED
  FORMAT_STRING = ('!QQ'  # tag, num_bytes_following (descriptor header)
                   'L'  # rollback_index_location
                   'L'  # partition_name_size (bytes)
                   'L' +  # public_key_size (bytes)
                   str(RESERVED) + 's')  # reserved

  def __init__(self, data=None):
    """Initializes a new chain partition descriptor.
    Arguments:
      data: If not None, must be a bytearray of size |SIZE|.
    Raises:
      LookupError: If the given descriptor is malformed.
    """
    AvbDescriptor.__init__(self, None)
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE
    if data:
      (tag, num_bytes_following, self.rollback_index_location,
       partition_name_len,
       public_key_len, _) = struct.unpack(self.FORMAT_STRING, data[0:self.SIZE])
      expected_size = round_to_multiple(
          self.SIZE - 16 + partition_name_len + public_key_len, 8)
      if tag != self.TAG or num_bytes_following != expected_size:
        raise LookupError('Given data does not look like a chain partition '
                          'descriptor.')
      o = 0
      self.partition_name = bytes(data[(self.SIZE + o):(self.SIZE + o +
                                                      partition_name_len)]).decode('utf-8')
      # Validate UTF-8 - decode() raises UnicodeDecodeError if not valid UTF-8.
      o += partition_name_len
      self.public_key = data[(self.SIZE + o):(self.SIZE + o + public_key_len)]
    else:
      self.rollback_index_location = 0
      self.partition_name = ''
      self.public_key = bytearray()

  def print_desc(self, o):
    """Print the descriptor.
    Arguments:
      o: The object to write the output to.
    """
    o.write('    Chain Partition descriptor:\n')
    o.write('      Partition Name:          {}\n'.format(self.partition_name))
    o.write('      Rollback Index Location: {}\n'.format(
        self.rollback_index_location))
    # Just show the SHA1 of the key, for size reasons.
    hexdig = hashlib.sha1(self.public_key).hexdigest()
    o.write('      Public key (sha1):       {}\n'.format(hexdig))

  def encode(self):
    """Serializes the descriptor.
    Returns:
      A bytearray() with the descriptor data.
    """
    encoded_name = self.partition_name.encode('utf-8')
    num_bytes_following = (
        self.SIZE + len(encoded_name) + len(self.public_key) - 16)
    nbf_with_padding = round_to_multiple(num_bytes_following, 8)
    padding_size = nbf_with_padding - num_bytes_following
    desc = struct.pack(self.FORMAT_STRING, self.TAG, nbf_with_padding,
                       self.rollback_index_location, len(encoded_name),
                       len(self.public_key), self.RESERVED*b'\0')
    padding = struct.pack(str(padding_size) + 'x')
    ret = desc + encoded_name + self.public_key + padding
    return bytearray(ret)

  def verify(self, image_dir, image_ext, expected_chain_partitions_map):
    """Verifies contents of the descriptor - used in verify_image sub-command.
    Arguments:
      image_dir: The directory of the file being verified.
      image_ext: The extension of the file being verified (e.g. '.img').
      expected_chain_partitions_map: A map from partition name to the
        tuple (rollback_index_location, key_blob).
    Returns:
      True if the descriptor verifies, False otherwise.
    """
    value = expected_chain_partitions_map.get(self.partition_name)
    if not value:
      sys.stderr.write('No expected chain partition for partition {}. Use '
                       '--expected_chain_partition to specify expected '
                       'contents.\n'.
                       format(self.partition_name))
      return False
    rollback_index_location, pk_blob = value
    if self.rollback_index_location != rollback_index_location:
      sys.stderr.write('Expected rollback_index_location {} does not '
                       'match {} in descriptor for partition {}\n'.
                       format(rollback_index_location,
                              self.rollback_index_location,
                              self.partition_name))
      return False
    if self.public_key != pk_blob:
      sys.stderr.write('Expected public key blob does not match public '
                       'key blob in descriptor for partition {}\n'.
                       format(self.partition_name))
      return False
    print ('{}: Successfully verified chain partition descriptor matches '
           'expected data'.format(self.partition_name))
    return True

DESCRIPTOR_CLASSES = [
    AvbPropertyDescriptor, AvbHashtreeDescriptor, AvbHashDescriptor,
    AvbKernelCmdlineDescriptor, AvbChainPartitionDescriptor
]

def parse_descriptors(data):
  """Parses a blob of data into descriptors.
  Arguments:
    data: A bytearray() with encoded descriptors.
  Returns:
    A list of instances of objects derived from AvbDescriptor. For
    unknown descriptors, the class AvbDescriptor is used.
  """
  o = 0
  ret = []
  while o < len(data):
    tag, nb_following = struct.unpack('!2Q', data[o:o + 16])
    if tag < len(DESCRIPTOR_CLASSES):
      c = DESCRIPTOR_CLASSES[tag]
    else:
      c = AvbDescriptor
    ret.append(c(bytearray(data[o:o + 16 + nb_following])))
    o += 16 + nb_following
  return ret

def calc_hash_level_offsets(image_size, block_size, digest_size):
  """Calculate the offsets of all the hash-levels in a Merkle-tree.
  Arguments:
    image_size: The size of the image to calculate a Merkle-tree for.
    block_size: The block size, e.g. 4096.
    digest_size: The size of each hash, e.g. 32 for SHA-256.
  Returns:
    A tuple where the first argument is an array of offsets and the
    second is size of the tree, in bytes.
  """
  level_offsets = []
  level_sizes = []
  tree_size = 0

  num_levels = 0
  size = image_size
  while size > block_size:
    num_blocks = (size + block_size - 1) / block_size
    level_size = round_to_multiple(num_blocks * digest_size, block_size)

    level_sizes.append(level_size)
    tree_size += level_size
    num_levels += 1

    size = level_size

  for n in range(0, num_levels):
    offset = 0
    for m in range(n + 1, num_levels):
      offset += level_sizes[m]
    level_offsets.append(int(offset))

  return level_offsets, int(tree_size)

def generate_hash_tree(image, image_size, block_size, hash_alg_name, salt,
                       digest_padding, hash_level_offsets, tree_size):
  """Generates a Merkle-tree for a file.
  Args:
    image: The image, as a file.
    image_size: The size of the image.
    block_size: The block size, e.g. 4096.
    hash_alg_name: The hash algorithm, e.g. 'sha256' or 'sha1'.
    salt: The salt to use.
    digest_padding: The padding for each digest.
    hash_level_offsets: The offsets from calc_hash_level_offsets().
    tree_size: The size of the tree, in number of bytes.
  Returns:
    A tuple where the first element is the top-level hash and the
    second element is the hash-tree.
  """
  hash_ret = bytearray(tree_size)
  hash_src_offset = 0
  hash_src_size = image_size
  level_num = 0
  while hash_src_size > block_size:
    level_output = b''
    remaining = hash_src_size
    while remaining > 0:
      hasher = hashlib.new(name=hash_alg_name, string=salt)
      # Only read from the file for the first level - for subsequent
      # levels, access the array we're building.
      if level_num == 0:
        image.seek(hash_src_offset + hash_src_size - remaining)
        data = image.read(min(remaining, block_size))
      else:
        offset = hash_level_offsets[level_num - 1] + hash_src_size - remaining
        data = hash_ret[offset:offset + block_size]
      hasher.update(data)

      remaining -= len(data)
      if len(data) < block_size:
        hasher.update(b'\0' * (block_size - len(data)))
      level_output += hasher.digest()
      if digest_padding > 0:
        level_output += b'\0' * digest_padding

    padding_needed = (round_to_multiple(
        len(level_output), block_size) - len(level_output))
    level_output += b'\0' * padding_needed

    # Copy level-output into resulting tree.
    offset = hash_level_offsets[level_num]
    hash_ret[offset:offset + len(level_output)] = level_output

    # Continue on to the next level.
    hash_src_size = len(level_output)
    level_num += 1

  hasher = hashlib.new(name=hash_alg_name, string=salt)
  hasher.update(level_output)
  return hasher.digest(), hash_ret

