from helper import (
    hash256,
    hash160,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    encode_varint,
    SIGHASH_ALL
)

class Block:

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
    
    # receives a stream of bytes that represent a block and returns a Block object - page 166.
    @classmethod
    def parse(cls, stream):
        # version is 4 bytes, LE. We interpret it as int for parsing.
        version = little_endian_to_int(stream.read(4))
        # previous block is 32 bytes, LE. prev_block is a 32-byte hash, that's why we don't interpret it as int.
        prev_block = stream.read(32)[::-1]
        # merkle root is 32 bytes, LE. merkle_root is a 32-byte hash, that's why we don't interpret it as int.
        merkle_root = stream.read(32)[::-1]
        # timestamp is 4 bytes, LE. We interpret it as int for parsing.
        timestamp = little_endian_to_int(stream.read(4))
        # bits is 4 bytes.
        bits = stream.read(4)
        # nonce is 4 bytes.
        nonce = stream.read(4)
        # we return a Block object.
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)