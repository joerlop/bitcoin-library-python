import hashlib
import math

from helper import (
    hash160,
    hash256,
)

# encodes num = converts num to byte format, LE.
def encode_num(num):
    return num.to_bytes(2, byteorder='little', signed=True)

# decodes num from byte format (LE) to int.
def decode_num(element):
    return int.from_bytes(element, 'little', signed=True)


