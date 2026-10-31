#!/usr/bin/env python3
"""Unit tests for the node #94 byte-indexed table offset checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded pointer rule on synthetic inputs.
They never execute the captured binary, and they write no 91 MB temporary
target copies: corruption checks run in memory.
"""

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_byte_indexed_table_offset import (  # noqa: E402
    BODY, CALLERS, END, START, analyze, compute_pointer,
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


class TestByteIndexedTableOffset(unittest.TestCase):
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
        self.assertEqual(compute_pointer(0x1000, True, 0, 3, True, 0x05, 0x40),
                         (0x1040, 0))
        self.assertEqual(compute_pointer(0x1000, False, 0, 3, True, 0x05, 0x40),
                         (0x1040, 0))
        self.assertEqual(compute_pointer(0x1000, False, 7, 3, True, 0x05, 0x40),
                         (0x14a0, 5))
        self.assertEqual(compute_pointer(0x1000, False, 7, 3, False, 0x05, 0x40),
                         (0x14a0, None))
        self.assertEqual(
            compute_pointer(0x1000, False, 7, 3, True, 0xff, 0x80000000),
            (0x8000ef20, 0xff))
        self.assertEqual(compute_pointer(0x1000, False, 7, 3, True, 0x00, 0x40),
                         (0x1040, 0))

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 0x47, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x2c0624
        data[off] = 0x00
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_caller_corruption_fails(self):
        data = load_bytes()
        write_va(data, CALLERS[0], b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
