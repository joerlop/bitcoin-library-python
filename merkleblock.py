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
        # We keep a pointer to a particular node in the tree, which will come handy later.
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
