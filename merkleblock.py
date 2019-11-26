import math

from io import BytesIO
from unittest import TestCase

from helper import (
    little_endian_to_int,
    merkle_parent,
    read_varint,
    bytes_to_bit_field
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

    # Find the merkle root given a flag bits list and a hashes list - page 209.
    # For a detailed explanation on how flag bits work see page 207.
    def populate_tree(self, flag_bits, hashes):
        # Loop until the root is calculated.
        while self.root() is None:
            # For leaf nodes, we are always given the hash.
            if self.is_leaf():
                # We remove the flag bit corresponding to this node.
                flag_bits.pop(0)
                # The hash at index 0 is the hash for this node.
                self.set_current_node(hashes.pop(0))
                self.up()
            else:
                left_hash = self.get_left_node()
                # If we don't have the left child value, there are 2 possibilities: 1) This node's value
                # may be in the hashes list or we need to calculate it.
                if left_hash is None:
                    # The next flag bit tells us whether we need to calculate this node or it is given to us.
                    # If the bit is a 0, it's hash is given to us. If it's a 1, we need to calculate it.
                    if flag_bits.pop(0) == 0:
                        self.set_current_node(hashes.pop(0))
                        # Now that we have set the value, we can go up and start working on the other side
                        # of the tree.
                        self.up()
                    # If the bit is not 0, we need to calculate this node's value, so we keep traversing to
                    # the left.
                    else:
                        self.left()
                # We check that the right node exists.
                elif self.right_exists():
                    right_hash = self.get_right_node()
                    # We have the left hash, but not the right. We traverse to the right node to get its value.
                    if right_hash is None:
                        self.right()
                    # We have both left and right hashes, so we calculate the parent to get the current node's value.
                    else:
                        self.set_current_node(
                            merkle_parent(left_hash, right_hash))
                        self.up()
                # We have the left node's value, but the right node does not exist. Thus, we calculate
                # the parent using the left node twice.
                else:
                    self.set_current_node(merkle_parent(left_hash, left_hash))
                    self.up()
        # All hashes must be consumed.
        if len(hashes) != 0:
            raise RuntimeError("Not all hashes were consumed.")
        # All flag bits must be consumed.
        for flag_bit in flag_bits:
            if flag_bit != 0:
                raise RuntimeError("All flag bits must be consumed.")


# The full node sends all the info. needed to verify an interesting transaction using a merkle block.
# The first 6 fields are exactly the same as the block header. The last 3 fields (total, hashes, flags)
# are the proof of inclusion.
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

    # Returns whether merkle root is valid for proof of inclusion given.
    def is_valid(self):
        flag_bits = bytes_to_bit_field(self.flags)
        hashes = [h[::-1] for h in self.hashes]
        merkle_tree = MerkleTree(self.total)
        merkle_tree.populate_tree(flag_bits, hashes)
        return merkle_tree.root()[::-1] == self.merkle_root
