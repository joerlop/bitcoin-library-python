from io import BytesIO
from logging import getLogger
from unittest import TestCase
import hashlib

from helper import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    h160_to_p2pkh_address,
    h160_to_p2sh_address,
    sha256,
    script_to_bech32
)

from op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
    op_hash160,
    op_equal,
    op_verify
)

LOGGER = getLogger(__name__)


# Takes the 20-byte hash160 part of the address and returns a p2pkh ScriptPubKey - page 140.
def p2pkh_script(h160):
    return Script([0x76, 0xa9, h160, 0x88, 0xac])


# Takes the 20-byte hash160 part of the address and returns a p2wpkh ScriptPubKey - page 234.
def p2wpkh_script(h160):
    return Script([0x00, h160])


# Takes a hash and returns the p2wsh ScriptPubKey.
def p2wsh_script(h256):
    return Script([0x00, h256])


# the Script object represents the command set that requires evaluation.
class Script:

    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            # each command is either an opcode to be executed or an element to be pushed onto the stack.
            self.cmds = cmds

    # takes a bytes stream and returns a Script object.
    @classmethod
    def parse(cls, s):
        # script serialization always starts with the length of the script.
        length = read_varint(s)
        cmds = []
        count = 0
        # parse until whole script has been parsed.
        while count < length:
            # this byte's value determines if we have an opcode or an element.
            current = s.read(1)
            count += 1
            # this converts the current byte into an int.
            current_byte_as_int = current[0]
            print('curr byte', current_byte_as_int)
            # for a number between 1 and 75, we know the next n bytes are an element.
            if current_byte_as_int >= 1 and current_byte_as_int <= 75:
                n = current_byte_as_int
                # push the element into the stack.
                cmds.append(s.read(n))
                # update the count.
                count += n
            # 76 is OP_PUSHDATA1, so the next byte tells us how many bytes the next element is.
            elif current_byte_as_int == 76:
                # n is the number of bytes to read
                n = little_endian_to_int(s.read(1))
                # push the element into the stack.
                cmds.append(s.read(n))
                # update the count.
                count += n + 1
            # 77 is OP_PUSHDATA2, so the next 2 bytes tell us how many bytes the next element is.
            elif current_byte_as_int == 77:
                n = little_endian_to_int(s.read(2))
                cmds.append(s.read(n))
                count += n + 2
            # else we push the opcode onto the stack
            else:
                op_code = current_byte_as_int
                cmds.append(op_code)
        # script should have consumed exactly the number of bytes expected. If not we raise an error.
        print("count, length", count, length)
        if count != length:
            raise SyntaxError('Parsing script failed.')
        return cls(cmds)

    # returns the serialization of the Script object.
    def raw_serialize(self):
        result = b''
        for cmd in self.cmds:
            # if it's an integer, we know it's an opcode because of the parse method.
            # Elements are pushed onto the stack as bytes.
            if type(cmd) == int:
                result += int_to_little_endian(cmd, 1)
            else:
                # number of bytes of the command.
                length = len(cmd)
                # if length <= 75, we encode the length of the element (cmd) as a single byte
                if length <= 75:
                    result += int_to_little_endian(length, 1)
                # for any element with length between 76 and 255, we put a OP_PUSHDATA1 first,
                # then encode the length as a single byte, followed by the element.
                elif length > 75 and length < 256:
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                # for any element with length between 256 and 520, we put a OP_PUSHDATA2 first,
                # then encode the length as 2 bytes, followed by the element.
                elif length >= 256 and length <= 520:
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('cmd is too long.')
                # we encode the cmd
                result += cmd
        return result

    # adds the length of the entire script to the beginning of the serialization as a varint.
    def serialize(self):
        result = self.raw_serialize()
        length = len(result)
        return encode_varint(length) + result

    # to evaluate a script, we need to combine the ScriptPubKey (lockbox) and ScriptSig fields (unlocking password).
    # to evaluate the 2 together, we take the commands from the ScriptSig and ScriptPubKey and combine them.
    def __add__(self, other):
        return Script(self.cmds + other.cmds)

    # z is the signature (scriptsig)
    def evaluate(self, z, witness, version=None, locktime=None, sequence=None):
        # get a copy of the commands array.
        cmds = self.cmds.copy()
        stack = []
        altstack = []
        # execute until commands array is empty.
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            print("cmd", cmd)
            # if command is an opcode.
            if type(cmd) == int:
                # get the function that executes the opcode from the OP_CODE_FUNCTIONS array.
                operation = OP_CODE_FUNCTIONS[cmd]
                # 99 and 100 are OP_IF and OP_NOTIF. They require manipulations of the cmds array based on
                # the top element of the stack.
                if cmd in (99, 100):
                    # if executing the opcode returns False (fails)
                    if not operation(stack, cmds):
                        LOGGER.info(f"bad op: {OP_CODE_NAMES[cmd]}")
                        return False
                # 107 and 108 are OP_TOALTSTACK and OP_FROMALTSTACK respectively. They move stack elements
                # to an alternate stack (altstack)
                elif cmd in (107, 108):
                    # if executing the opcode returns False (fails)
                    if not operation(stack, altstack):
                        LOGGER.info(f"bad op: {OP_CODE_NAMES[cmd]}")
                        return False
                # 172, 173, 174 and 175 are OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY
                # all require the signature hash z for validation.
                elif cmd in (172, 173, 174, 175):
                    # if executing the opcode returns False (fails)
                    if not operation(stack, z):
                        LOGGER.info(f"bad op: {OP_CODE_NAMES[cmd]}")
                        return False
                # 177 is OP_CHECKLOCKTIMEVERIFY. Requires locktime and sequence.
                elif cmd == 177:
                    # if executing the opcode returns False (fails)
                    if not operation(stack, locktime, sequence):
                        LOGGER.info(f"bad op: {OP_CODE_NAMES[cmd]}")
                        return False
                # 177 is OP_CHECKSEQUENCEVERIFY. Requires sequence and version.
                elif cmd == 178:
                    # if executing the opcode returns False (fails)
                    if not operation(stack, version, sequence):
                        LOGGER.info(f"bad op: {OP_CODE_NAMES[cmd]}")
                        return False
                else:
                    # if executing the opcode returns False (fails)
                    if not operation(stack):
                        LOGGER.info(f"bad op: {OP_CODE_NAMES[cmd]}")
                        return False
            # if cmd is not an opcode, it's an element. We push it to the stack.
            else:
                stack.append(cmd)
                # We check if the commands follow the p2wsh special rule.
                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 32:
                    # The top element is the sha256 hash of the WitnessScript.
                    s256 = stack.pop()
                    # The second element is the witness version.
                    stack.pop()
                    # Everything but the WitnessScript is added to the command set.
                    cmds.extend(witness[:-1])
                    witness_script = witness[-1]
                    s256_calculated = sha256(witness_script)
                    if s256 != s256_calculated:
                        print(
                            f"Bad sha256 {s256.hex()} vs. {s256_calculated.hex()}")
                        return False
                    stream = BytesIO(encode_varint(
                        len(witness_script)) + witness_script)
                    witness_script_cmds = Script.parse(stream).cmds
                    cmds.extend(witness_script_cmds)
                # We check if the commands follow the p2wpkh special rule - page 235.
                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 20:
                    h160 = stack.pop()
                    stack.pop()
                    cmds.extend(witness)
                    cmds.extend(p2pkh_script(h160).cmds)
                # we check if next commands form the pattern that executes the special p2sh rule - page 152 and 156.
                # if that is the case, the last cmd appended would be the RedeemScript, which is an element.
                # That's why we check for the next 3 commands only.
                # Specifically, we check that they are: OP_HASH160 (0xa9), a hash element and OP_EQUAL(0x87).
                if len(cmds) == 3 and cmds[0] == 0xa9 and type(cmds[1]) == bytes and len(cmds[1]) == 20 and cmds[2] == 0x87:
                    # we run the sequence manually.
                    cmds.pop()
                    # the only value we need to save is the hash, the other two we know are OP_HASH160 and OP_EQUAL.
                    h160 = cmds.pop()
                    cmds.pop()
                    # first we perform the op_hash160 on the current stack, which hashes the top element of the stack.
                    if not op_hash160(stack):
                        return False
                    # then we push the hash160 we got in the commands to the stack.
                    stack.append(h160)
                    # next we perform an op_equal, which compares the 2 top most elements of the stack.
                    if not op_equal(stack):
                        return False
                    # next we need to check if the element left on the stack is a 1, which is what op_verify does.
                    if not op_verify(stack):
                        LOGGER.info('bad p2sh h160')
                        return False
                    # if we got to this point, we know cmd is the RedeemScrtipt.
                    # to be able to parse it, we need to prepend its length.
                    redeem_script = encode_varint(len(cmd)) + cmd
                    # we convert the script into a stream of bytes.
                    stream = BytesIO(redeem_script)
                    # we get the parsed script
                    parsed_script = Script.parse(stream)
                    # we extend the commands set with the commands from the parsed RedeemScript.
                    cmds.extend(parsed_script.cmds)
        # if stack is empty after running all the commands, we fail the script returning False.
        if len(stack) == 0:
            return False
        # if the stack's top element is an empty byte, which is how the stack stores a 0, we fail the script.
        if stack.pop() == b'':
            return False
        # any other result means the script is valid.
        return True

    # returns whether this script follows the p2sh special rule: OP_HASH160, 20-byte hash, OP_EQUAL.
    def is_p2sh_script_pubkey(self):
        # there should be exactly 3 cmds
        # OP_HASH160 (0xa9), 20-byte hash, OP_EQUAL (0x87)
        return len(self.cmds) == 3 and self.cmds[0] == 0xa9 and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20 and self.cmds[2] == 0x87

    def is_p2pkh_script_pubkey(self):
        '''Returns whether this follows the
        OP_DUP OP_HASH160 <20 byte hash> OP_EQUALVERIFY OP_CHECKSIG pattern.'''
        # there should be exactly 5 cmds
        # OP_DUP (0x76), OP_HASH160 (0xa9), 20-byte hash, OP_EQUALVERIFY (0x88),
        # OP_CHECKSIG (0xac)
        return len(self.cmds) == 5 and self.cmds[0] == 0x76 and self.cmds[1] == 0xa9 and type(self.cmds[2]) == bytes and len(self.cmds[2]) == 20 and self.cmds[3] == 0x88 and self.cmds[4] == 0xac

    # Returns whether this script follows the p2wpkh script: OP_0, <20-byte hash> - page 225.
    def is_p2wpkh_script_pubkey(self):
        return len(self.cmds) == 2 and self.cmds[0] == 0x00 and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20

    # Returns whether this script follows the p2wsh script: OP_0, <32-byte hash> - page 236.
    def is_p2wsh_script_pubkey(self):
        return len(self.cmds) == 2 and self.cmds[0] == 0x00 and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 32

    # Returns the address corresponding to the script
    def address(self, testnet=False):
        print('address', self.cmds)
        if self.is_p2pkh_script_pubkey():  # p2pkh
            print('p2pkh')
            # hash160 is the 3rd cmd
            h160 = self.cmds[2]
            # convert to p2pkh address using h160_to_p2pkh_address (remember testnet)
            return h160_to_p2pkh_address(h160, testnet)
        elif self.is_p2sh_script_pubkey():  # p2sh
            # hash160 is the 2nd cmd
            h160 = self.cmds[1]
            # convert to p2sh address using h160_to_p2sh_address (remember testnet)
            return h160_to_p2sh_address(h160, testnet)
        elif self.is_p2wpkh_script_pubkey():
            witver = self.cmds[0]
            script = self.cmds[1]
            print('bech32 addr', script_to_bech32(script, witver, testnet))
            return script_to_bech32(script, witver, testnet)
        elif self.is_p2wsh_script_pubkey():
            witver = self.cmds[0]
            script = self.cmds[1]
            print('bech32 addr', script_to_bech32(script, witver, testnet))
            return script_to_bech32(script, witver, testnet)
        elif self.cmds[0] == 106:
            return 'OP_RETURN'
        raise ValueError('Unknown ScriptPubKey')
