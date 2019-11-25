import math

from io import BytesIO
from unittest import TestCase

from helper import (
    little_endian_to_int,
    merkle_parent,
    read_varint,
)


class MerkleTree:

    # The only info. we need to build the structure of a merkle tree is the number of leaves (total) - page 200.
    def __init__(self, total):
        self.total = total
        # Since we halve at every level, log2 of the number of levels is how many levels there are in the merkle tree - page 199.
        self.max_depth = math.ceil(math.log(self.total, 2))
        # The merkle tree will hold the root at index 0, the level below at index 1 and so on.
        self.nodes = []
        # There are 0 to max_depth levels in this merkle tree.
        for depth in range(self.max_depth + 1):
            # At any particular level, the number of nodes is the number of total leaves divided by 2
            # for every level above the leaf level.
            num_items = math.ceil(self.total / 2**(self.max_depth - depth))
            # We don't know yet what any of the hashes are, so we set them to None.
            level_hashes = [None] * num_items
            # self.nodes will be a list of lists, or a 2-dimensional array.
            self.nodes.append(level_hashes)
        # We keep a pointer to a particular node in the tree.
        # These will be used to keep track of where we are and be able to traverse the tree.
        self.current_depth = 0
        self.current_index = 0

    def __repr__(self):
        result = []
        for depth, level in enumerate(self.nodes):
            items = []
            for index, h in enumerate(level):
                if h is None:
                    short = 'None'
                else:
                    short = f"{h.hex()[:8]}"
                if depth == self.current_depth and index == self.current_index:
                    items.append(f"*{short[:-2]}*")
                else:
                    items.append(f"{short}")
            result.append(', '.join(items))
        return '\n'.join(result)

    # Traverse from a child to a parent node.
    # Note: self.nodes[depth][index] are the coordinates of any node within the self.nodes 2dimensional array.
    def up(self):
        # To go up we subtract 1 from the depth
        self.current_depth -= 1
        # And we do floor division by 2.
        self.current_index //= 2
        # This way, for example, if we have a child at position self.nodes[3][0], we know that the parent will be
        # at [2][0].

    # Go from a parent node to the child node that is to its left.
    def left(self):
        self.current_depth += 1
        self.current_index *= 2

    # Same as left but to the right.
    def right(self):
        self.current_depth += 1
        self.current_index = self.current_index * 2 + 1

    # Returns the root of the tree, which we know is at position [0][0].
    def root(self):
        return self.nodes[0][0]

    # Set the current node to a given value.
    def set_current_node(self, value):
        self.nodes[self.current_depth][self.current_index] = value

    # Returns the current node.
    def get_current_node(self):
        return self.nodes[self.current_depth][self.current_index]

    # Returns the child node to the left.
    def get_left_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2]

    # Returns the child node to the right.
    def get_right_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2 + 1]

    # Returns whether this is a leaf node.
    def is_leaf(self):
        return self.current_depth == self.max_depth

    # In certain situations, we won't have a right child because we may be at the furthest right node
    # of a level whose child level has an odd number of items.
    def right_exists(self):
        return len(self.nodes[self.current_depth + 1]) > self.current_index * 2 + 1


# The full node sends all the info. needed to verify an interesting transaction using a merkle block.
# The first 6 fields are exactly the same as the block header. The last 3 fields (total, hashes, flags)
# are the proof if inclusion.
class MerkleBlock:

    command = b'merkleblock'

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, total, hashes, flags):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        # Total number of transactions in the block. Will be the number of leaves of the merkle tree.
        self.total = total
        # Transaction hashes given to us needed to verify the interesting transaction.
        self.hashes = hashes
        # The flags give information about where the hashes go within the merkle tree.
        self.flags = flags

    # Receives a stream and returns a class object - page 205.
    @classmethod
    def parse(cls, stream):
        version = little_endian_to_int(stream.read(4))
        prev_block = stream.read(32)[::-1]
        merkle_root = stream.read(32)[::-1]
        timestamp = little_endian_to_int(stream.read(4))
        bits = stream.read(4)
        nonce = stream.read(4)
        total = little_endian_to_int(stream.read(4))
        num_hashes = read_varint(stream)
        hashes = []
        for _ in range(num_hashes):
            hashes.append(stream.read(32)[::-1])
        flags_length = read_varint(stream)
        flags = stream.read(flags_length)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce, total, hashes, flags)
