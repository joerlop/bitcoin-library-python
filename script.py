from io import BytesIO
from logging import getLogger
from unittest import TestCase

from helper import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)

from op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)

LOGGER = getLogger(__name__)


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
                count += n
            # 77 is OP_PUSHDATA2, so the next 2 bytes tell us how many bytes the next element is.
            elif current_byte_as_int == 77:
                n = little_endian_to_int(s.read(2))
                cmds.append(s.read(n))
                count += n
            # else we push the opcode onto the stack
            else:
                op_code = current_byte_as_int
                cmds.append(op_code)
        # script should have consumed exactly the number of bytes expected. If not we raise an error.
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
    
    # to evaluate a script, we need to combine the ScriptPubKey (lockbox) and ScriptSig fields (unlocking password).
    # to evaluate the 2 together, we take the commands from the ScriptSig and ScriptPubKey and combine them.
    def __add__(self, other):
        return Script(self.cmds + other.cmds)
