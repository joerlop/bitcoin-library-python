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
            raise SyntaxError(
                f"Magic is not right: {magic.hex()} vs. {expected_magic.hex()}")
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

    # returns the bytes serialization of this NetworkEnvelope object - page 179.
    def serialize(self):
        magic = self.magic
        # make the command exactly 12 bytes.
        command = self.command + b'\x00' * (12 - len(self.command))
        # we need to convert the payload length from int to LE bytes.
        payload_length = int_to_little_endian(len(self.payload), 4)
        payload = self.payload
        # compute the payload checksum, which is first 4 bytes of hash256 of payload.
        payload_checksum = hash256(self.payload)[:4]
        # return the concatenation
        return magic + command + payload_length + payload_checksum + payload


class VersionMessage:

    def __init__(self, version=70015, services=0, timestamp=None, receiver_services=0,
                 receiver_ip=b'\x00\x00\x00\x00', receiver_port=8333, sender_services=0,
                 sender_ip=b'\x00\x00\x00\x00', sender_port=8333, nonce=None,
                 user_agent=b'programmingbitcoin:0.1', latest_block=0, relay=False):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2**64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    # returns the VersionMessage in bytes format.
    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += int_to_little_endian(self.services, 8)
        result += int_to_little_endian(self.timestamp, 8)
        result += int_to_little_endian(self.receiver_services, 8)
        result += b'\x00' * 10 + b'\xff\xff' + self.receiver_ip
        result += int_to_little_endian(self.receiver_port, 2)
        result += int_to_little_endian(self.sender_services, 8)
        result += b'\x00' * 10 + b'\xff\xff' + self.sender_ip
        result += int_to_little_endian(self.sender_port, 2)
        result += self.nonce
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        result += int_to_little_endian(self.latest_block, 4)
        if self.relay:
            result += b'\x01'
        else:
            result += b'\x00'
        return result
