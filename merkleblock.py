import math

from io import BytesIO
from unittest import TestCase

from helper import (
    bytes_to_bit_field,
    little_endian_to_int,
    merkle_parent,
    read_varint,
)
