from unittest import TestCase

from helper import (
    bit_field_to_bytes,
    encode_varint,
    int_to_little_endian,
    murmur3,
)

BIP37_CONSTANT = 0xfba4c795


# Page 215.
class BloomFilter:

    def __init__(self, size, function_count, tweak):
        # The size of the bit field, or how many buckets there are.
        self.size = size
        self.bit_field = [0] * (size * 8)
        # The number of hash functions to use to calculate the bloom filter.
        self.function_count = function_count
        # A tweak to be able to change the bloom filter slightly if it hits too many items.
        self.tweak = tweak
