#!/usr/bin/env python3
"""ULEB128 width/truncation controls for wei_buffered_cap's CIE parser.

The sibling parser in tools/fde_extents.py already rejects truncated or
oversized ULEB128 records; the copy inside tools/wei_buffered_cap.py is
used on the same .eh_frame CIE fields and must fail closed the same way,
with the tool's EvidenceError, instead of returning values wider than
64 bits or crashing with IndexError on a truncated record.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import wei_buffered_cap as tool

uleb = tool.uleb
EvidenceError = tool.EvidenceError


def cie_body(code_align):
    """Minimal version-1 CIE body (after the CIE id) with a zR augmentation."""
    body = bytearray(64)
    body[4] = 1                      # version
    body[5:8] = b'zR\x00'            # augmentation string
    i = 8
    body[i:i + len(code_align)] = code_align
    i += len(code_align)
    body[i] = 1                      # data alignment factor
    i += 1
    body[i] = 0                      # return address register (version 1)
    i += 1
    body[i] = 1                      # augmentation length
    i += 1
    body[i] = 0x1b                   # R encoding: pcrel | sdata4
    return bytes(body)


class FakeImg:
    def __init__(self, body):
        self.body = body

    def read(self, va, size):
        return self.body[:size]


def cie_r_encoding(body):
    fdes = object.__new__(tool.Fdes)
    fdes.img = FakeImg(body)
    return fdes.cie_r_encoding(0)


class UlebWidthTests(unittest.TestCase):
    def test_valid_values_and_offsets(self):
        self.assertEqual(uleb(b'\x00', 0), (0, 1))
        self.assertEqual(uleb(b'\xe5\x8e\x26', 0), (624485, 3))
        # Nonminimal encodings within ten bytes stay accepted.
        self.assertEqual(uleb(b'\x80\x00', 0), (0, 2))
        # The largest 64-bit value is the valid endpoint.
        self.assertEqual(uleb(b'\xff' * 9 + b'\x01', 0), ((1 << 64) - 1, 10))
        self.assertEqual(uleb(b'\x80' * 9 + b'\x01', 0), (1 << 63, 10))

    def test_overflowing_terminal_byte_rejected(self):
        for terminal in range(2, 128):
            with self.subTest(terminal=terminal):
                with self.assertRaises(EvidenceError):
                    uleb(b'\x80' * 9 + bytes([terminal]), 0)

    def test_overlong_encoding_rejected(self):
        with self.assertRaises(EvidenceError):
            uleb(b'\x80' * 10 + b'\x01', 0)
        with self.assertRaises(EvidenceError):
            uleb(b'\xff' * 10 + b'\x7f', 0)

    def test_truncated_encoding_rejected(self):
        for buf in (b'', b'\x80', b'\x80' * 9, b'\xff' * 5):
            with self.subTest(buf=buf):
                with self.assertRaises(EvidenceError):
                    uleb(buf, 0)

    def test_cie_valid_encoding_still_read(self):
        self.assertEqual(cie_r_encoding(cie_body(b'\x01')), 0x1b)

    def test_cie_overflowing_alignment_rejected(self):
        with self.assertRaises(EvidenceError):
            cie_r_encoding(cie_body(b'\x80' * 9 + b'\x02'))

    def test_cie_truncated_alignment_rejected(self):
        body = bytearray(cie_body(b'\x01'))
        body[8:] = b'\x80' * (len(body) - 8)
        with self.assertRaises(EvidenceError):
            cie_r_encoding(bytes(body))


if __name__ == '__main__':
    unittest.main()
