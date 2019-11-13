from io import BytesIO
from unittest import TestCase

import json
import requests

from helper import (
    hash256,
    int_to_little_endian,
    little_endian_to_int
)

# page 88
class Tx:
    def __init__(self, version, tx_inputs, tx_outputs, locktime, testnet=False):
        self.version = version
        self.tx_inputs = tx_inputs
        self.tx_outputs = tx_outputs
        self.locktime = locktime
        self.testnet = testnet
    
    def __repr__(self):
        tx_inputs = ''
        for tx_input in self.tx_inputs:
            tx_inputs += tx_input.__repr__() + '\n'
        tx_outputs = ''
        for tx_output in self.tx_outputs:
            tx_outputs += tx_output.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ninputs:\n{}\noutputs:\n{}locktime: {}'.format(self.id(), self.version, tx_inputs, tx_outputs, self.locktime)

    # hexadecimal value of transaction hash
    def id(self):
        return self.hash().hex()
    
    # binary hash of the serialization in little endian 
    def hash(self):
        return hash256(self.seralize())[::-1]
    
    # receives a stream of bytes and returns a Tx object
    @classmethod
    def parse(cls, stream):
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(stream.read(4)) 
        