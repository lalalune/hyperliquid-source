#!/usr/bin/env python3
"""Unit tests for the node #94 eight-byte binary search checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded binary search rule on synthetic
inputs. They never execute the captured binary, and they write no 91 MB
temporary target copies: corruption checks run in memory.
"""

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_eight_byte_binary_search import (  # noqa: E402
    BODY, CALLERS, END, START, analyze, binary_search,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'


def load_bytes():
    return bytearray(TARGET.read_bytes())


def sections_of(data):
    from elf_index import sections
    return {s['name']: s for s in sections(bytes(data))}


def write_va(data, va, raw):
    secs = sections_of(data)
    for s in secs.values():
        if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']:
            off = s['offset'] + va - s['address']
            data[off:off + len(raw)] = raw
            return
    raise ValueError(f'unmapped VA {hex(va)}')


class TestEightByteBinarySearch(unittest.TestCase):
    def test_check_reproduces(self):
        result = analyze(bytes(load_bytes()))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['direct_callers'], CALLERS)
        self.assertEqual(result['relocation_slots'], [])

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(binary_search([10, 20, 30], 30, 20), 1)
        self.assertEqual(binary_search([10, 20, 30], 30, 25), 2)
        self.assertEqual(binary_search([10, 20, 30], 30, 5), 0)
        self.assertEqual(binary_search([10, 20, 30], 30, 31), 2)
        self.assertEqual(binary_search([10, 20, 30], 30, 30), 2)
        self.assertEqual(binary_search([10, 20, 30], 100, 50), 3)
        self.assertEqual(binary_search([], 5, 3), 0)
        self.assertEqual(binary_search([], 0, 0), 0xffffffffffffffff)
        self.assertEqual(binary_search([7], 10, 7), 0)
        self.assertEqual(binary_search([7], 10, 8), 1)
        self.assertEqual(binary_search([1 << 63], (1 << 64) - 1, 1), 0)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 0x72, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x2ac1ec
        data[off] = 0x00
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END + 5, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_caller_corruption_fails(self):
        data = load_bytes()
        write_va(data, 0x52cab17 + 1, b'\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_rule_spot(self):
        # Spot values hand-computed from the retained bytes, not execution:
        # keys [5, 15, 25, 35], limit 100: search 26 -> mid 2 (25) < 26,
        # count 1, lo 3; mid 0 (35) >= 26, mid 0 -> index 3.
        self.assertEqual(binary_search([5, 15, 25, 35], 100, 26), 3)
        # keys [5, 15, 25, 35], limit 100: search 15 -> mid 2 (25) >= 15,
        # count 2; mid 1 (15) >= 15, count 1; mid 0 (5) < 15 -> index 1.
        self.assertEqual(binary_search([5, 15, 25, 35], 100, 15), 1)


if __name__ == '__main__':
    unittest.main()
