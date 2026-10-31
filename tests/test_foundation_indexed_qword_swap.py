#!/usr/bin/env python3
"""Unit tests for the node #94 indexed qword swap checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded swap rule on synthetic inputs.
They never execute the captured binary, and they write no 91 MB temporary
target copies: corruption checks run in memory.
"""

import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_indexed_qword_swap import (  # noqa: E402
    BODY, CALLERS, END, MASK, START, analyze, element_pointer,
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


class TestIndexedQwordSwap(unittest.TestCase):
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
        self.assertEqual(element_pointer(0x1000, 0x2000, 3), 0x1018)
        self.assertEqual(element_pointer(0x1000, 0x2000, 0x1f), 0x10f8)
        self.assertEqual(element_pointer(0x1000, 0x2000, 0x20), 0x2000)
        self.assertEqual(element_pointer(0x1000, 0x2000, 0x25), 0x2028)
        self.assertEqual(element_pointer(0x3000, 0x4000, 5), 0x3028)
        self.assertEqual(element_pointer(0x3000, 0x4000, 0x20), 0x4000)
        # Swap effect on a synthetic memory: values exchange, pointers kept.
        mem = {0x1018: 0xaaaa, 0x3028: 0xbbbb}
        pa = element_pointer(0x1000, 0x2000, 3)
        pb = element_pointer(0x3000, 0x4000, 5)
        mem[pa], mem[pb] = mem[pb], mem[pa]
        self.assertEqual((mem[pa], mem[pb]), (0xbbbb, 0xaaaa))
        self.assertEqual(element_pointer(0xfffffffffffffff8, 0x2000, 3), 0x10)
        self.assertEqual(element_pointer(0x1000, 0xfffffffffffffff8, 0x20),
                         0xfffffffffffffff8)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 4, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_branch_target_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 4, b'\x76\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_caller_corruption_fails(self):
        data = load_bytes()
        write_va(data, CALLERS[0], b'\xe8\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        # FDE range field at .eh_frame+0x28bba4+12.
        off = eh['offset'] + 0x28bba4 + 12
        data[off:off + 4] = struct.pack('<I', 0x6a)
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
