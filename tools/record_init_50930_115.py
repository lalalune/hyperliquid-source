"""Model of node #115 routine 0x5d50930: initialize one record in place.

The routine takes one argument, the destination record pointer in
rdi, makes no calls, and writes only constants: no input besides
the pointer is read. The writes, in the order the routine issues
them (offset: width = value):

    +0x00: 8 = 0, +0x08: 2 = 0, +0x0a: 1 = 0, +0x0c: 4 = 4,
    +0x10: 1 = 0, +0x18: 16 = 0, +0x28: 16 = 0, +0x38: 16 = 0,
    +0x48: 8 = 0, +0x50: 2 = 0x100, +0x58: 8 = 0,
    +0x60: 8 = 0x00ffffffffffffff, +0x68: 4 = 0, +0x6c: 2 = 0,
    +0x70: 8 = 0, +0x78: 4 = 0, +0x7c: 2 = 0, +0x80: 8 = 0,
    +0xf0: 16 = 0

Bytes inside 0x00..0x100 that the routine never touches keep their
previous value: 0x0b, 0x11..0x17, 0x52..0x57, 0x6e..0x6f,
0x7e..0x7f, 0x88..0xef. Nothing outside 0x00..0x100 is written.
At ret, rax still holds 0x00ffffffffffffff; whether any caller
reads that register value is not claimed.

The model is data-only: the record is a mutable bytearray of at
least 0x100 bytes. It raises on a short buffer as a model safety
property, not a binary claim (the binary's behaviour for a null
or short destination is not claimed).
"""

import struct

RECORD_SIZE = 0x100

# (offset, width, value) in the order the routine issues the writes.
WRITES = (
    (0x00, 8, 0),
    (0x08, 2, 0),
    (0x0A, 1, 0),
    (0x0C, 4, 4),
    (0x10, 1, 0),
    (0x18, 16, 0),
    (0x28, 16, 0),
    (0x38, 16, 0),
    (0x48, 8, 0),
    (0x50, 2, 0x100),
    (0x58, 8, 0),
    (0x60, 8, 0x00FFFFFFFFFFFFFF),
    (0x68, 4, 0),
    (0x6C, 2, 0),
    (0x70, 8, 0),
    (0x78, 4, 0),
    (0x7C, 2, 0),
    (0x80, 8, 0),
    (0xF0, 16, 0),
)

# Byte ranges inside 0x00..0x100 that the routine never touches.
UNTOUCHED = (
    (0x0B, 0x0C),
    (0x11, 0x18),
    (0x52, 0x58),
    (0x6E, 0x70),
    (0x7E, 0x80),
    (0x88, 0xF0),
)

RETURN_RAX = 0x00FFFFFFFFFFFFFF


def initialize_record(record):
    """Apply the routine's writes to a bytearray of >= 0x100 bytes.

    Returns RETURN_RAX, the value left in rax at ret. Untouched
    bytes are preserved exactly.
    """
    if not isinstance(record, bytearray):
        raise TypeError("record must be a bytearray")
    if len(record) < RECORD_SIZE:
        raise ValueError("record must be at least 0x100 bytes")
    for offset, width, value in WRITES:
        if width == 16:
            record[offset:offset + 16] = b"\x00" * 16
        else:
            fmt = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}[width]
            struct.pack_into(fmt, record, offset, value)
    return RETURN_RAX
