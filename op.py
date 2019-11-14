import hashlib
import math

from helper import (
    hash160,
    hash256,
)

# encodes num = converts num to byte format, LE.
def encode_num(num):
    if num == 0:
        return b''
    # absolute value of num.
    abs_num = abs(num)
    # negative boolean.
    negative = num < 0
    # The bytearray() method returns a bytearray object which is a mutable (can be modified) 
    # sequence of integers in the range 0 <= x < 256.
    result = bytearray()
    # loops abs_num byte by byte and appends each byte to the result.
    while abs_num:
        # appends abs_num in byte format to result.
        result.append(abs_num & 0xff)
        # shifts to the next byte.
        abs_num >>= 8
    # if the top bit is set,
    # for negative numbers we ensure that the top bit is set.
    # for positive numbers we ensure that the top bit is not set.
    # this is because when the top bit is zero, the number is positive. 
    # when it's 1, the number is negative.
    if result[-1] & 0x80: # True only if top bit is a 1
        # if top bit is already a 1, I need to add a byte to indicate it's negative or positive.
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    # if top bit isn't a 1, but number is negative, then I change top bit for a 1.
    elif negative:
        # ensures that top bit is 1
        result[-1] |= 0x80
    return bytes(result)

# decodes num from byte format to int.
def decode_num(element):
    if element == b'':
        return 0
    # reverse for big endian
    big_endian = element[::-1]
    # top bit being 1 means it's negative
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8
        result += c
    if negative:
        return -result
    else:
        return result

"""
The following methods (until op_16) just add encoded numbers to the stack.
"""

def op_0(stack):
    stack.append(encode_num(0))
    return True


def op_1negate(stack):
    stack.append(encode_num(-1))
    return True


def op_1(stack):
    stack.append(encode_num(1))
    return True


def op_2(stack):
    stack.append(encode_num(2))
    return True


def op_3(stack):
    stack.append(encode_num(3))
    return True


def op_4(stack):
    stack.append(encode_num(4))
    return True


def op_5(stack):
    stack.append(encode_num(5))
    return True


def op_6(stack):
    stack.append(encode_num(6))
    return True


def op_7(stack):
    stack.append(encode_num(7))
    return True


def op_8(stack):
    stack.append(encode_num(8))
    return True


def op_9(stack):
    stack.append(encode_num(9))
    return True


def op_10(stack):
    stack.append(encode_num(10))
    return True


def op_11(stack):
    stack.append(encode_num(11))
    return True


def op_12(stack):
    stack.append(encode_num(12))
    return True


def op_13(stack):
    stack.append(encode_num(13))
    return True


def op_14(stack):
    stack.append(encode_num(14))
    return True


def op_15(stack):
    stack.append(encode_num(15))
    return True


def op_16(stack):
    stack.append(encode_num(16))
    return True

# does nothing
def op_nop(stack):
    return True

# if the top stack value is not 0, the statements are executed. The top stack value is removed.
def op_if(stack, items):
    # if there's nothing in the stack, return False
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    # number of endifs needed to exit the if.
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        # 99 and 100 are OP_IF and OP_NOTIF, so it would mean we have a nested loop.
        if item in (99, 100):
            # we increase the # of endifs needed to exit the if.
            num_endifs_needed += 1
            # add the OP_IF or OP_NOTIF to the if statement array.
            current_array.append(item)
        # 103 is OP_ELSE and if we only needed 1 endif, then we exit the if and get into the else statement. 
        elif num_endifs_needed == 1 and item == 103:
            # else statement items.
            current_array = false_items
        # 104 is and OP_ENDIF
        elif item == 104:
            # if we only needed 1 endif, exit the if statement.
            if num_endifs_needed == 1:
                found = True
                break
            else:
                # else, subtract 1 to the endifs needed to exit the if statement.
                num_endifs_needed -= 1
                # add the OP_ENDIF to the if statement array.
                current_array.append(item)
        # for any other operation or element, add it to the if statement array.
        else:
            current_array.append(item)
    # if items array is empty and we didn't exit the if statement, return False.
    if not found:
        return False
    # get the top element from the stack
    element = stack.pop()
    # if top stack element is 0, statements are not executed.
    if decode_num(element) == 0:
        items[:0] = false_items
    # else, they are executed.
    else:
        items[:0] = true_items
    return True

# duplicates the top element of the stack and pushes it to the stack.
def op_dup(stack):
    # if stack is empty, return False
    if len(stack) < 1:
        return False
    top_element = stack[-1]
    stack.append(top_element)
    return True

# consumes top element of the stack, performs a hash256 operation on it and pushes the hashed element
# into the stack.
def op_hash256(stack):
    # if stack is empty, return False
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash256(element))
    return True

# consumes top element of the stack, performs a hash160 operation on it and pushes the hashed element
# into the stack.
def op_hash160(stack):
    # if stack is empty, return False
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash160(element))
    return True