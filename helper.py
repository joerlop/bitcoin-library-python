from unittest import TestSuite, TextTestRunner

import hashlib

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
SIGHASH_ALL = 1
# represents the number of seconds in 2 weeks.
TWO_WEEKS = 60 * 60 * 24 * 14
MAX_TARGET = 0xffff * 256**(0x1d - 3)


def run(test):
    suite = TestSuite()
    suite.addTest(test)
    TextTestRunner().run(suite)


def hash256(s):
    '''two rounds of sha256'''
    # sha256 returns a SHA-256 hash object. The digest serializes it to byte format (bytes object).
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

# helper function necessary for address creation - page 83


def hash160(s):
    '''sha256 followed by ripemd160'''
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


# receives a number s in bytes format and returns a string as its base58 encoded version
def encode_base58(s):
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


# helper function necessary for address creation - page 83
def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])


# Takes an address and returns its 20-byte hash version. Opposite of encode_base58 - Page 139.
def decode_base58(s):
    num = 0
    # we get to the encoded version doing modulo 58 and then dividing the number by 58 until
    # we get to a number igual to or less than 58. We reverse that in this loop.
    for c in s:
        num *= 58
        # index method finds returns the index of c within the BASE58_ALPHABET string.
        num += BASE58_ALPHABET.index(c)
    # we convert the number to big endian bytes.
    num_bytes = num.to_bytes(25, byteorder='big')
    # we know that the checksum is the last 4 bytes.
    checksum = num_bytes[-4:]
    # we check that the checksum is correct.
    if hash256(num_bytes[:-4])[:4] != checksum:
        raise ValueError(f"bad address")
    # the first byte is the network prefix (mainnet or testnet) and the last 4 are the checksum.
    # The middle 20 are the 20_byte hash (the hash160).
    return num_bytes[1:-4]


def little_endian_to_int(num_bytes):
    return int.from_bytes(num_bytes, 'little')


def int_to_little_endian(num, length):
    return num.to_bytes(length, 'little')


# reads a varint (variable integer) from a stream - page 92
def read_varint(stream):
    # i could be a prefix or an integer. If it's a prefix, it will indicate how big the number is. Else, it is the number.
    i = stream.read(1)[0]
    # if i is 0xfd, next two bytes are the number
    if i == 0xfd:
        return little_endian_to_int(stream.read(2))
    # if i is 0xfe, next 4 bytes are the number
    elif i == 0xfe:
        return little_endian_to_int(stream.read(4))
    # if i is 0xfe, next 8 bytes are the number
    elif i == 0xff:
        return little_endian_to_int(stream.read(8))
    # else, the number is i
    else:
        return i


# converts (encodes) an integer to a varint. Opposite of read_varint - page 92
def encode_varint(i):
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise RuntimeError('integer too large: {}'.format(i))


# function that converts a 20-byte hash160 into a p2sh address.
def h160_to_p2pkh_address(h160, testnet=False):
    # prefix depends on address being testnet or mainnet
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    # combine prefix with hash 160 of sec
    combined = prefix + h160
    return encode_base58_checksum(combined)


# function that converts a 20-byte hash160 into a p2sh address.
def h160_to_p2sh_address(h160, testnet=False):
    if testnet:
        return encode_base58_checksum(b'\xc4' + h160)
    else:
        return encode_base58_checksum(b'\x05' + h160)


# converts a block header's bits field into the target value - page 172.
# the target is important because a valid proof-of-work is a hash of the block header that, when interpreted
# as little endian int, is below the target.
def bits_to_target(bits):
    # last byte of bits field is the exponent.
    exponent = bits[-1]
    # remainder of the bits field is the coefficient.
    coefficient = little_endian_to_int(bits[:-1])
    # we calculate the target as follows
    target = coefficient * 256**(exponent - 3)
    return target


# receives a target int and returns the bits in bytes - page 175.
def target_to_bits(target):
    # convert int to 4 bytes (32 bits), BE
    raw_bytes = target.to_bytes(32, 'big')
    # get rid of all the leading zeros.
    raw_bytes = raw_bytes.lstrip((b'\x00'))
    # The bits format is a way to express large numbers succinctly and can be used with both positive and
    # negative numbers.
    # If the first bit in the coefficient is a 1, the bits field is interpreted as a negative number.
    # Since the target is always positive for our usecase, we shift everything over by 1 byte if the first bit is 1.
    # if the first byte is bigger than 0x7f (127), it means the first bit has to be a 1, because in binary 1000 0000 is 128.
    if raw_bytes[0] > 0x7f:
        # the exponent is how long the number is in base 256.
        exponent = len(raw_bytes) + 1
        # the coefficient is the first three digits of the base 256 number
        coefficient = b'\x00' + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)
        coefficient = raw_bytes[:3]
    # the coefficient is in LE and the exponent goes last in the bits format.
    bits = coefficient[::-1] + bytes([exponent])
    return bits


# returns new bits after a 2.016 block period - page 175.
def calculate_new_bits(previous_bits, time_differential):
    # ensures max. increase in difficulty to be x4.
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    # ensures max. decrease in difficulty to be /4.
    elif time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4
    # calculate the new target based on time differential.
    new_target = bits_to_target(previous_bits) * time_differential // TWO_WEEKS
    # if the new target is bigger than MAX_TARGET, set to MAX_TARGET
    if new_target > MAX_TARGET:
        new_target = MAX_TARGET
    # compute new bits based on new target.
    new_bits = target_to_bits(new_target)
    return new_bits
