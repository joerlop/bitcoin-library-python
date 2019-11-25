from helper import (
    hash256,
    hash160,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    encode_varint,
    SIGHASH_ALL,
    bits_to_target,
    merkle_root
)

GENESIS_BLOCK = bytes.fromhex(
    '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')
TESTNET_GENESIS_BLOCK = bytes.fromhex(
    '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18')
LOWEST_BITS = bytes.fromhex('ffff001d')


class Block:

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        # The tx_hashes are used to calculate the merkle root - page 195.
        self.tx_hashes = tx_hashes

    # receives a stream of bytes that represent a block and returns a Block object - page 166.
    @classmethod
    def parse(cls, stream):
        # version is 4 bytes, LE. We interpret it as int for parsing.
        version = little_endian_to_int(stream.read(4))
        # previous block is 32 bytes, LE. prev_block is a 32-byte hash, that's why we don't interpret it as int, but leave as bytes.
        prev_block = stream.read(32)[::-1]
        # merkle root is 32 bytes, LE. merkle_root is a 32-byte hash, that's why we don't interpret it as int, but leave it as bytes.
        merkle_root = stream.read(32)[::-1]
        # timestamp is 4 bytes, LE. We interpret it as int for parsing.
        timestamp = little_endian_to_int(stream.read(4))
        # bits is 4 bytes. Left as bytes for parsing.
        bits = stream.read(4)
        # nonce is 4 bytes. Left as bytes for parsing.
        nonce = stream.read(4)
        # we return a Block object.
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    # from a Block object, returns its serialization in bytes format. Opposite from parse.
    def serialize(self):
        version = int_to_little_endian(self.version, 4)
        prev_block = self.prev_block[::-1]
        merkle_root = self.merkle_root[::-1]
        timestamp = int_to_little_endian(self.timestamp, 4)
        bits = self.bits
        nonce = self.nonce
        return version + prev_block + merkle_root + timestamp + bits + nonce

    # returns the hash256 of the block's serialization - page 167
    def hash(self):
        block_hash = hash256(self.serialize())
        return block_hash[::-1]

    # returns whether the block is using BIP9 - page 168.
    def bip9(self):
        # checks if the first 3 bits of version are equal to 001, which would mean the miner is using BIP9.
        return self.version >> 29 == 0b001

    # returns whether the block is signaling for BIP91 - page 168.
    def bip91(self):
        # if bit 4 of version is a 1, it means miner is signaling for BIP91.
        # Note that bit 0 is the rightmost bit.
        return self.version >> 4 & 1 == 1

    # returns whether the block is signaling for BIP141 - page 168.
    def bip141(self):
        # if bit 1 of version is a 1, it means miner is signaling for BIP141.
        # Note that bit 0 is the rightmost bit.
        return self.version >> 1 & 1 == 1

    def target(self):
        return bits_to_target(self.bits)

    # returns the difficulty for this block - page 173.
    def difficulty(self):
        # compute the target.
        target = self.target()
        # calculate the difficulty using its formula.
        difficulty = 0xffff * 256**(0x1d-3) / target
        return difficulty

    # returns whether this block is valid. Whether it's proof of work is valid - page 174.
    def check_pow(self):
        # first we get the header in bytes format.
        block_header = self.serialize()
        # we do a hash256 on the block's header.
        h256 = hash256(block_header)
        # we interpret it as a LE integer.
        proof = little_endian_to_int(h256)
        # if this value is smaller than the target, we have a valid proof of work.
        return proof < self.target()

    # Returns whether the merkle root is valid for this block comparing the header merkle root
    # with the merkle root calculated using the transaction hashes.
    def validate_merkle_root(self):
        # We have to reverse each tx hash to be able to validate it first.
        hashes = [h[::-1] for h in self.tx_hashes]
        # We calculate the merkle root using the transaction hashes.
        # We need to reverse the result.
        calculated_merkle = merkle_root(hashes)[::-1]
        # Return the result of the comparison.
        return self.merkle_root == calculated_merkle
