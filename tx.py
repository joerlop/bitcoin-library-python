from io import BytesIO
from unittest import TestCase

import json
import requests

from helper import (
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    encode_varint
)


# class that represents a Bitcoin transaction - page 88
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
    def parse(cls, stream, testnet=False):
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(stream.read(4)) 
        # number of inputs
        num_inputs = read_varint(stream)
        # initialize inputs array
        inputs = []
        # loop num_inputs times to get all inputs from the stream. 
        for _ in num_inputs:
            # appends a TxIn object to inputs array
            inputs.append(TxIn.parse(stream))
        # get the number of outputs
        num_outputs = read_varint(stream)
        outputs = []
        # loop num_outputs times to get all outputs from the stream. 
        for _ in num_outputs:
            outputs.append(TxOut.parse(stream))
        # locktime is 4 bytes, little endian
        locktime = little_endian_to_int(stream.read(4))
        # return a Tx object
        return cls(version, inputs, outputs, locktime, testnet)

# class that represents a transaction input - page 95
class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        self.script_sig = script_sig
        self.sequence = sequence

   # receives a bytes stream, returns a TxIn object 
    @classmethod
    def parse(cls, stream):
        # prev_tx is 32 bytes, little endian. Parsed this way because it's a hash.
        prev_tx = stream.read(32)[::-1]
        # prev_index is 4 bytes, little endian.
        prev_index = little_endian_to_int(stream.read(4))
        # TODO:
        script_sig = Script.parse(stream)
        # sequence is 4 bytes, little endian.
        sequence = little_endian_to_int(stream.read(4))
        # returns an object of the same class.
        return cls(prev_tx, prev_index, script_sig, sequence)
    
    # returns the bytes serialization from a TxIn object
    def seralize(self):
        # just need to reverse order of previous tx hash.
        prev_tx = self.prev_tx[::-1]
        # get prev_index in byte format.
        prev_index = int_to_little_endian(self.prev_index, 4)
        # get script_sig in byte format.
        script_sig = self.script_sig.seralize() 
        # get sequence in byte_format.
        sequence = int_to_little_endian(self.sequence, 4)
        return prev_tx + prev_index + script_sig + sequence

# class that represents a transaction output
class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = #script_pubkey
    
    def __repr__(self):
        return f"{self.amount}:{self.script_pubkey}"
    
    # receives a bytes stream, returns a TxOut object 
    @classmethod
    def parse(cls, stream):
        # prev_tx is 32 bytes, little endian. Parsed this way because it's a hash.
        amount = little_endian_to_int(stream.read(8))
        # TODO:
        script_pubkey = Script.parse(stream)
        # returns an object of the same class.
        return cls(amount, script_pubkey)
    
    # returns the bytes serialization of a TxOut object
    def serialize(self):
        # get the amount in byte format.
        amount = int_to_little_endian(self.amount, 8)
        # get the script_pubkey in byte format.
        script_pubkey = self.script_pubkey.seralize()