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
        # command is an ASCII string identifying the packet content
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


# When a node creates an outgoing connection, it will immediately advertise its version.
# The remote node will respond with its version.
# No further communication is possible until both peers have exchanged their version.
class VersionMessage:

    command = b'version'

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


# The verack message is sent in reply to version.
# This message consists of only a message header with the command string "verack".
class VerAckMessage:

    command = b'verack'

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b''


# The ping message is sent primarily to confirm that the TCP/IP connection is still valid.
# An error in transmission is presumed to be a closed connection and the address is removed as a current peer.
class PingMessage:

    command = b'ping'

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


# The pong message is sent in response to a ping message.
# In modern protocol versions, a pong response is generated using a nonce included in the ping.
class PongMessage:

    command = b'pong'

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class SimpleNode:

    def __init__(self, host, port=None, testnet=False, logging=False):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        self.testnet = testnet
        self.logging = logging
        # socket.socket() is used to create a socket object.
        # AF_INET is the Internet address family for IPv4.
        # we specify the socket type (2nd argument) as socket.SOCK_STREAM because
        # when you do that, the default protocol that’s used is the Transmission Control Protocol (TCP).
        # This is a good default and probably what you want.
        # TCP relieves you from having to worry about packet loss, data arriving out-of-order,
        # and many other things that invariably happen when you’re communicating across a network.
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # connect() is used to connect to the server. host is the server's IP address and port is the
        # port used by the server.
        self.socket.connect((host, port))
        # we create a stream to be able to read from the socket. A stream made this way can be
        # passed to all the parse methods - page 181.
        self.stream = self.socket.makefile('rb', None)

    # send a message to the connected node.
    def send(self, message):
        # the command property and serialize method are expected to exist in the message object - page 183.
        envelope = NetworkEnvelope(
            message.command, message.serialize(), self.testnet)
        if self.logging:
            print(f"sending: {envelope}")
        self.socket.sendall(envelope.serialize())

    # reads a new mesage from the socket - page 182.
    def read(self):
        envelope = NetworkEnvelope.parse(self.stream, testnet=self.testnet)
        if self.logging:
            print(f"receiving: {envelope}")
        return envelope

    # lets us wait for any one of several commands (message classes) - page 183.
    # note: a commercial-strength would not use something like this.
    def wait_for(self, *message_classes):
        command = None
        command_to_class = {m.command: m for m in message_classes}
        while command not in command_to_class.keys():
            envelope = self.read()
            command = envelope.command
            if command == VersionMessage.command:
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                self.send(PongMessage(envelope.payload))
        return command_to_class[command].parse(envelope.stream())
