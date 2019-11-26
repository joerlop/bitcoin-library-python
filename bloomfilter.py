from unittest import TestCase

from helper import (
    bit_field_to_bytes,
    encode_varint,
    int_to_little_endian,
    murmur3,
)

from network import GenericMessage

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

    # Given an item to be added to the bloom filter, sets the corresponding bits of the bit field to 1.
    def add(self, item):
        # We hash function_count number of times.
        for i in range(self.function_count):
            # This is the seed formula - page 215.
            seed = i * BIP37_CONSTANT + self.tweak
            # murmur3 returns a number, so we don't have to convert to an integer.
            h = murmur3(item, seed=seed)
            bit = h % self.bit_field
            self.bit_field[bit] = 1

    # Generates the payload to communicate the bloom filter to a full node
    # and returns a GenericMessage that includes it - page 217.
    def filterload(self, flag=1):
        payload = encode_varint(self.size)
        payload += bit_field_to_bytes(self.bit_field)
        payload += int_to_little_endian(self.function_count, 4)
        payload += int_to_little_endian(self.tweak, 4)
        # The matched item flag is used to tell the full node to add any matched transactions to the bloom filter.
        payload += int_to_little_endian(flag, 1)
        # filterload is the command used to set the bloom filter.
        return GenericMessage(b'filterload', payload)
