"""Tests for tools/record_init_50930_115.py, the model of node #115
routine 0x5d50930. The oracle is the routine's own write table:
nineteen constant writes, six untouched ranges inside 0x00..0x100,
no calls, and rax left holding 0x00ffffffffffffff at ret.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from record_init_50930_115 import (  # noqa: E402
    RECORD_SIZE, RETURN_RAX, UNTOUCHED, WRITES, initialize_record)

CHECKS = [0]


def check(condition, label):
    CHECKS[0] += 1
    if not condition:
        raise AssertionError(label)


def expect_raises(kind, fn, label):
    CHECKS[0] += 1
    try:
        fn()
    except kind:
        return
    except Exception as exc:  # noqa: BLE001 - any other error is a failure
        raise AssertionError("%s: wrong exception %r" % (label, exc))
    raise AssertionError("%s: no exception" % label)


def read(record, offset, width):
    fmt = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}[width]
    return struct.unpack_from(fmt, record, offset)[0]


def main():
    check(RECORD_SIZE == 0x100, "record footprint is 0x100 bytes")
    check(len(WRITES) == 19, "nineteen writes")
    check(RETURN_RAX == 0x00FFFFFFFFFFFFFF, "return rax is the +0x60 constant")

    # A record pre-filled with a sentinel keeps the sentinel exactly
    # on every untouched byte and receives every written constant.
    record = bytearray(b"\xAB" * RECORD_SIZE)
    rax = initialize_record(record)
    check(rax == RETURN_RAX, "rax holds 0x00ffffffffffffff at ret")
    for offset, width, value in WRITES:
        if width == 16:
            check(record[offset:offset + 16] == b"\x00" * 16,
                  "16-byte zero block at %#x" % offset)
        else:
            check(read(record, offset, width) == value,
                  "write at %#x is %#x" % (offset, value))
    for start, stop in UNTOUCHED:
        check(record[start:stop] == b"\xAB" * (stop - start),
              "untouched range %#x..%#x preserved" % (start, stop))

    # The three non-zero constants are the record's pinned shape.
    record = bytearray(RECORD_SIZE)
    initialize_record(record)
    check(read(record, 0x0C, 4) == 4, "+0x0c dword is 4")
    check(read(record, 0x50, 2) == 0x100, "+0x50 word is 0x100")
    check(read(record, 0x60, 8) == 0x00FFFFFFFFFFFFFF,
          "+0x60 qword is 0x00ffffffffffffff")
    check(record[0x50] == 0, "+0x50 low byte is 0")

    # Second initialization is idempotent on an already-initialized
    # record, and a longer buffer keeps its tail untouched.
    before = bytes(record)
    initialize_record(record)
    check(bytes(record) == before, "re-initialization is idempotent")
    long_record = bytearray(b"\xCD" * 0x140)
    initialize_record(long_record)
    check(long_record[0x100:] == b"\xCD" * 0x40,
          "nothing written past 0x100")

    # Model guards (not binary claims).
    expect_raises(ValueError, lambda: initialize_record(bytearray(0x80)),
                  "short buffer rejected")
    expect_raises(TypeError, lambda: initialize_record(bytes(RECORD_SIZE)),
                  "immutable buffer rejected")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
