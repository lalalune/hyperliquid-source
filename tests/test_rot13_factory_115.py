"""Tests for the node #115 ROT13BlockCipher factory model (tools/rot13_factory_115.py).

Expectations are grounded in the binary (work/hl-node-115.bin):
  * 0x5ff7120 splits the spec at the first ':'; no colon -> block size 32.
  * The suffix is parsed base-10 (strtoull via 0x61d1540); empty or
    non-numeric suffixes are rejected.
  * Vtable slots 20/21 (0x5fef9b0 / 0x5fef9f0) add 13 (mod 256) to each of
    the first block_size bytes, with no alphabet check.
  * Map 0x65052c0 holds one entry, "block_size": type 22, verification 1,
    flags 0x400, offset 0.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from rot13_factory_115 import (  # noqa: E402
    DEFAULT_BLOCK_SIZE,
    GROUP_BASE_OFFSET,
    GROUP_MAP,
    GROUP_NAME,
    MAP_ENTRIES,
    OBJECT_SIZE,
    VTABLE,
    Rot13BlockCipher,
    SpecError,
    create_cipher,
    parse_block_size,
    rot13_block,
)


class TestParseBlockSize(unittest.TestCase):
    def test_no_colon_defaults_to_32(self):
        self.assertEqual(parse_block_size("ROT13"), 32)
        self.assertEqual(parse_block_size(""), 32)
        self.assertEqual(parse_block_size("anything-at-all"), 32)

    def test_colon_suffix_parsed_decimal(self):
        self.assertEqual(parse_block_size("ROT13:16"), 16)
        self.assertEqual(parse_block_size("x:0"), 0)
        self.assertEqual(parse_block_size("a:1"), 1)
        self.assertEqual(parse_block_size("ROT13:007"), 7)

    def test_first_colon_wins(self):
        # The factory splits at the FIRST ':'; "b:3" is not a number.
        with self.assertRaises(SpecError):
            parse_block_size("a:b:3")

    def test_empty_suffix_rejected(self):
        with self.assertRaises(SpecError):
            parse_block_size("ROT13:")

    def test_non_numeric_suffix_rejected(self):
        for bad in ("ROT13:abc", "ROT13:16x", "ROT13:-1", "ROT13: 16"):
            with self.assertRaises(SpecError, msg=bad):
                parse_block_size(bad)

    def test_overflow_rejected(self):
        with self.assertRaises(OverflowError):
            parse_block_size("ROT13:18446744073709551616")  # 2**64


class TestRot13Block(unittest.TestCase):
    def test_letters_shift_by_13(self):
        self.assertEqual(rot13_block(b"abc", 3), b"nop")

    def test_no_wraparound_at_z(self):
        # Byte-wise +13 does NOT wrap within the alphabet: 'n' + 13 is
        # '{', not 'a'. The binary transform is not letter-ROT13 and
        # not self-inverse.
        self.assertEqual(rot13_block(b"nop", 3), b"{|}")
        self.assertEqual(rot13_block(b"xyz", 3), bytes([0x85, 0x86, 0x87]))

    def test_only_first_n_bytes(self):
        self.assertEqual(rot13_block(b"abcd", 1), b"nbcd")
        self.assertEqual(rot13_block(b"abcd", 0), b"abcd")

    def test_no_alphabet_check(self):
        # The binary adds 13 to EVERY byte, not just letters.
        self.assertEqual(rot13_block(b" ", 1), b"-")  # 0x20 + 13 = 0x2d
        self.assertEqual(rot13_block(bytes([0xF5]), 1), bytes([0x02]))

    def test_short_buffer_rejected(self):
        with self.assertRaises(ValueError):
            rot13_block(b"ab", 3)


class TestCipherObject(unittest.TestCase):
    def test_layout_and_group(self):
        cipher = Rot13BlockCipher(32)
        self.assertEqual(cipher.vtable, VTABLE)
        self.assertEqual(cipher.size, OBJECT_SIZE)
        self.assertEqual(cipher.block_size, 32)
        group = cipher.groups[0]
        self.assertEqual(group["name"], GROUP_NAME)
        self.assertEqual(group["base_offset"], GROUP_BASE_OFFSET)
        self.assertEqual(group["map"], GROUP_MAP)
        self.assertEqual(
            group["entries"]["block_size"],
            {"type": 22, "verification": 1, "flags": 0x400, "offset": 0},
        )
        self.assertEqual(len(group["entries"]), 1)

    def test_map_entry_constants(self):
        self.assertEqual(MAP_ENTRIES["block_size"]["type"], 22)
        self.assertEqual(MAP_ENTRIES["block_size"]["verification"], 1)
        self.assertEqual(DEFAULT_BLOCK_SIZE, 32)

    def test_create_replaces_slot(self):
        slot = [None]
        new, old = create_cipher("ROT13:16", slot)
        self.assertIs(slot[0], new)
        self.assertIsNone(old)
        self.assertEqual(new.block_size, 16)
        self.assertEqual(new.transform(b"abcd" + b"\x00" * 12),
                         b"nopq" + b"\x0d" * 12)
        prev, old = create_cipher("plain", slot)
        self.assertIs(slot[0], prev)
        self.assertIs(old, new)  # the old object is handed back for destroy
        self.assertEqual(prev.block_size, 32)


if __name__ == "__main__":
    unittest.main()
