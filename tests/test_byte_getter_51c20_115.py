"""Tests for the node #115 byte getter model
(tools/byte_getter_51c20_115.py, RE-001 work item
RE-001-byte-getter-51c20-115). Each check counts; the run prints
"<n> checks pass" on success.

Expectations are target-grounded: the flag test is equality with
1 (not truthiness), a non-negative selector under flag 1 returns
0 without reading the vector or the default, a negative selector
under flag 1 falls back to the vector rule, and the vector rule
returns the first byte when non-empty and the +0x153 default
byte when empty -- all read from the whole-function excerpt in
the packet.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from byte_getter_51c20_115 import ByteSource, byte_getter

CHECKS = [0]


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


def expect_raises(fn, label):
    try:
        fn()
    except (ValueError, TypeError):
        CHECKS[0] += 1
    else:
        raise AssertionError(label)


def main():
    # Flag != 1: vector rule, selector never consulted.
    check(byte_getter(ByteSource(0, 5, b"\x41\x42", 0x99)) == 0x41,
          "flag 0 returns first vector byte")
    check(byte_getter(ByteSource(2, -7, b"\x41", 0x99)) == 0x41,
          "flag 2 (not truthy-gated) returns first vector byte")
    check(byte_getter(ByteSource(255, 0, b"", 0x99)) == 0x99,
          "flag 255 with empty vector returns default")
    check(byte_getter(ByteSource(0, -1, b"", 0x00)) == 0x00,
          "flag 0 with empty vector returns default 0")
    # Only the first vector byte is read.
    check(byte_getter(ByteSource(0, 9, b"\x41\x42\x43", 0x99)) == 0x41,
          "bytes past the first never change the result")
    check(byte_getter(ByteSource(0, 9, b"\x41", 0x99))
          == byte_getter(ByteSource(0, 9, b"\x41\xff\xff", 0x99)),
          "vector tail is unobserved")

    # Flag == 1, selector >= 0: literal 0, vector/default ignored.
    check(byte_getter(ByteSource(1, 0, b"\x41", 0x99)) == 0,
          "flag 1 selector 0 returns 0")
    check(byte_getter(ByteSource(1, 123456, b"\x41", 0x99)) == 0,
          "flag 1 positive selector returns 0")
    check(byte_getter(ByteSource(1, 2147483647, b"", 0x99)) == 0,
          "flag 1 max int32 selector returns 0 even with empty vector")
    check(byte_getter(ByteSource(1, 7, b"", 0x00)) == 0,
          "flag 1 positive selector returns 0 even when default is 0")

    # Flag == 1, selector < 0: vector rule again.
    check(byte_getter(ByteSource(1, -1, b"\x42", 0x99)) == 0x42,
          "flag 1 negative selector returns first vector byte")
    check(byte_getter(ByteSource(1, -2147483648, b"", 0x77)) == 0x77,
          "flag 1 min int32 selector with empty vector returns default")
    check(byte_getter(ByteSource(1, -1, b"\x00\xff", 0x99)) == 0x00,
          "first vector byte may itself be 0")

    # Input guards (model safety, not binary claims).
    expect_raises(lambda: byte_getter(None), "null source raises")
    expect_raises(lambda: ByteSource(256, 0, b"", 0),
                  "flag above byte range raises")
    expect_raises(lambda: ByteSource(-1, 0, b"", 0),
                  "negative flag raises")
    expect_raises(lambda: ByteSource(True, 0, b"", 0),
                  "bool flag raises")
    expect_raises(lambda: ByteSource(1, 2147483648, b"", 0),
                  "selector above int32 raises")
    expect_raises(lambda: ByteSource(1, -2147483649, b"", 0),
                  "selector below int32 raises")
    expect_raises(lambda: ByteSource(1, 0, "AB", 0),
                  "non-bytes vector raises")
    expect_raises(lambda: ByteSource(1, 0, b"", 256),
                  "default above byte range raises")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
