import socket
import time

from io import BytesIO
from random import randint
from unittest import TestCase

from block import Block
from helper import (
    hash256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'

class NetworkEnvelope:

    def __init__(self, command, payload, testnet=False):
        self.command = command
        self.payload = payload
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC
    
    def __repr__(self):
        return '{}: {}'.format(self.command.decode('ascii'), self.payload.hex())

    # receives a stream of bytes representing a NetworkEnvelope and returns an object of the class.
    @classmethod
    def parse(cls, stream, testnet=False):
        # first 4 bytes are the magic.
        magic = stream.read(4)
        # check that we received a magic.
        if magic == b'':
            raise IOError('Connection reset!')
        # check that magic is correct.
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC
        if expected_magic != magic:
            raise SyntaxError(f"Magic is not right: {magic.hex()} vs. {expected_magic.hex()}")
        # next 12 are the command.
        command = stream.read(12)
        # strip command from leading zeros.
        command = command.strip(b'\x00')
        # next 4 are the payload length, in LE.
        payload_length = little_endian_to_int(stream.read(4))
        # next 4 are the payload checksum.
        payload_checksum = stream.read(4)
        # next is the payload.
        payload = stream.read(payload_length)
        # check checksum is correct.
        calculated_checksum = hash256(payload)[:4]
        if payload_checksum != calculated_checksum:
            raise IOError('checksum does not match')
        return cls(command, payload, testnet)