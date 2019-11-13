from unittest import TestSuite, TextTestRunner

import hashlib

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


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

# receives a binary number s and returns its base58 encoded version
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
