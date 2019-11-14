import hashlib
import math

from helper import (
    hash160,
    hash256,
)

# encodes num = converts num to byte format, LE.
def encode_num(num):
    if num == 0:
        return b''
    # absolute value of num.
    abs_num = abs(num)
    # negative boolean.
    negative = num < 0
    # The bytearray() method returns a bytearray object which is a mutable (can be modified) 
    # sequence of integers in the range 0 <= x < 256.
    result = bytearray()
    # loops abs_num byte by byte and appends each byte to the result.
    while abs_num:
        # appends abs_num in byte format to result.
        result.append(abs_num & 0xff)
        # shifts to the next byte.
        abs_num >>= 8
    # if the top bit is set,
    # for negative numbers we ensure that the top bit is set.
    # for positive numbers we ensure that the top bit is not set.
    # this is because when the top bit is zero, the number is positive. 
    # when it's 1, the number is negative.
    if result[-1] & 0x80: # True only if top bit is a 1
        # if top bit is already a 1, I need to add a byte to indicate it's negative or positive.
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    # if top bit isn't a 1, but number is negative, then I change top bit for a 1.
    elif negative:
        # ensures that top bit is 1
        result[-1] |= 0x80
    return bytes(result)

# decodes num from byte format to int.
def decode_num(element):
    if element == b'':
        return 0
    # reverse for big endian
    big_endian = element[::-1]
    # top bit being 1 means it's negative
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8
        result += c
    if negative:
        return -result
    else:
        return result
