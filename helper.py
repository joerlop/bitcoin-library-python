from unittest import TestSuite, TextTestRunner

import hashlib

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def run(test):
    suite = TestSuite()
    suite.addTest(test)
    TextTestRunner().run(suite)


def hash256(s):
    '''two rounds of sha256'''
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

def little_endian_to_int(num_bin):
    return int.from_bytes(num_bin, 'little')

def int_to_little_endian(num, length):
    return num.to_bytes(length, 'little')