r"""Tests for the node #115 backslash-root prefix model
(tools/backslash_root_prefix_141c3a0_115.py, RE-001 work item
RE-001-backslash-root-prefix-141c3a0-115). Each check counts; the
run prints "<n> checks pass" on success.

Expectations are target-grounded, read from the whole-function
excerpt in the packet: the empty buffer is false; a leading
backslash is true at any length; length 1 and length 2 are false
unless the single leading backslash already matched; byte[1] and
(when present) byte[3] must begin a character (continuation bytes
0x80..0xbf fail the signed ``cmpb $0xc0 .. jl`` guard); and the
drive-letter-style ``?:\`` case returns byte[1]==':' & byte[2]=='\'.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from backslash_root_prefix_141c3a0_115 import (
    backslash_root_prefix,
    _is_continuation,
)

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
    # Step 1: empty buffer is false.
    check(backslash_root_prefix(b"") is False, "empty is false")

    # Step 2: a leading backslash is true, independent of length.
    check(backslash_root_prefix(b"\\") is True, "lone backslash is true")
    check(backslash_root_prefix(b"\\abc") is True, "backslash prefix is true")
    check(backslash_root_prefix(b"\\\\") is True, "UNC-style backslash is true")
    # The leading-backslash case wins before the continuation guard
    # on byte[1] is ever reached.
    check(backslash_root_prefix(b"\\\x80") is True,
          "backslash wins even if byte[1] is a continuation byte")

    # Step 3: length 1 with a non-backslash byte is false.
    check(backslash_root_prefix(b"C") is False, "lone non-backslash is false")
    check(backslash_root_prefix(b":") is False, "lone colon is false")

    # Step 4: byte[1] must begin a character. 0x80..0xbf fail.
    check(backslash_root_prefix(b"C\x80\\") is False,
          "continuation byte at index 1 fails")
    check(backslash_root_prefix(b"C\xbf\\") is False,
          "0xbf at index 1 fails")
    # 0x3a (':') is not a continuation byte, so the guard passes.
    check(_is_continuation(0x3A) is False, "colon is a char boundary")
    check(_is_continuation(0x7F) is False, "0x7f is a char boundary")
    check(_is_continuation(0xC0) is False, "0xc0 is a char boundary")
    check(_is_continuation(0x80) is True, "0x80 is a continuation byte")
    check(_is_continuation(0xBF) is True, "0xbf is a continuation byte")

    # Step 5: length 2 (no leading backslash) is false.
    check(backslash_root_prefix(b"C:") is False, "drive letter + colon only is false")
    check(backslash_root_prefix(b"ab") is False, "two plain bytes are false")

    # Step 7 at length 3: the drive-letter-style root.
    check(backslash_root_prefix(b"C:\\") is True, "C:\\ is a backslash root")
    check(backslash_root_prefix(b"z:\\") is True, "any first byte: z:\\ is a root")
    check(backslash_root_prefix(b"1:\\") is True,
          "first byte need not be alphabetic")
    check(backslash_root_prefix(b"C:/") is False,
          "forward slash variant is not this routine's true case")
    check(backslash_root_prefix(b"C;\\") is False,
          "byte[1] must be exactly ':'")
    check(backslash_root_prefix(b"CA\\") is False,
          "byte[1] must be ':' not a letter")

    # Step 6 at length > 3: byte[3] must begin a character.
    check(backslash_root_prefix(b"C:\\a") is True,
          "C:\\ followed by an ASCII start is true")
    check(backslash_root_prefix(b"C:\\\xc3\xa9") is True,
          "C:\\ followed by a 2-byte char start (0xc3) is true")
    check(backslash_root_prefix(b"C:\\\x80") is False,
          "C:\\ followed by a continuation byte at index 3 is false")
    check(backslash_root_prefix(b"C:\\\xbf") is False,
          "0xbf at index 3 is false")
    # Length exactly 3 never reads byte[3]; length 4 with a boundary
    # byte[3] agrees with the length-3 result.
    check(backslash_root_prefix(b"C:\\") == backslash_root_prefix(b"C:\\a"),
          "length-3 and boundary-extended length-4 agree")

    # Only the first backslash of a leading run matters; a backslash
    # that is not at index 0 or inside the ?:\\ pattern is irrelevant.
    check(backslash_root_prefix(b"a\\b") is False,
          "a backslash at index 1 is not a root")
    check(backslash_root_prefix(b"ab\\") is False,
          "a backslash at index 2 without ':' at index 1 is not a root")

    # Model safety guard (not a binary claim).
    expect_raises(lambda: backslash_root_prefix("C:\\"), "str argument raises")
    expect_raises(lambda: backslash_root_prefix(None), "None argument raises")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
