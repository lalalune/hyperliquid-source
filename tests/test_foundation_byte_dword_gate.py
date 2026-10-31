#!/usr/bin/env python3
"""Unit tests for the node #94 byte/dword-gate evidence checker.

The tests run the checker against a copy of the pinned target and against
corrupted copies, plus the decoded gate rule on synthetic inputs.
They never execute the captured binary.
"""

import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_byte_dword_gate import (  # noqa: E402
    BODY, END, START, gate, inspect,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-byte-dword-gate-94/evidence.json'


def load():
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


class TestByteDwordGate(unittest.TestCase):
    def test_check_reproduces(self):
        result = inspect(str(TARGET))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(len(result['direct_callers']), 3)
        self.assertEqual(result['relocation_slots'], [])

    def test_body_hash(self):
        data = load()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(gate(5, 3, 0, 0), 5)
        self.assertEqual(gate(5, 0, 1, 3), 1)
        self.assertEqual(gate(5, -1, 1, 3), 1)
        self.assertEqual(gate(0, 3, 1, 3), 1)
        self.assertEqual(gate(0, 3, 5, 3), 0)
        self.assertEqual(gate(0, 3, 3, 3), 1)
        self.assertEqual(gate(0xFF, 1, 9, 9), 255)
        self.assertEqual(gate(0, 1, -1, 0), 1)
        self.assertEqual(gate(0, 1, 0, -1), 0)

    def corrupted(self, mutator):
        data = load()
        mutator(data)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(bytes(data))
            path = tmp.name
        try:
            with self.assertRaises(ValueError):
                inspect(path)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_corrupt_body_byte(self):
        def flip(data):
            write_va(data, START + 4, b'\x00')
        self.corrupted(flip)

    def test_corrupt_padding(self):
        def flip(data):
            write_va(data, END, b'\x90')
        self.corrupted(flip)

    def test_corrupt_fde(self):
        def flip(data):
            secs = sections_of(data)
            eh = secs['.eh_frame']
            off = eh['offset'] + 0x29c460 + 12
            data[off] ^= 0x01
        self.corrupted(flip)

    def test_corrupt_call_site(self):
        def flip(data):
            write_va(data, 0x503a9b7 + 1, b'\x00')
        self.corrupted(flip)

    def test_corrupt_caller_setup(self):
        def flip(data):
            write_va(data, 0x514ae46 - 7, b'\x00')
        self.corrupted(flip)

    def test_corrupt_neighbor_jump(self):
        def flip(data):
            write_va(data, 0x5172cb0 + 1, b'\x00')
        self.corrupted(flip)


if __name__ == '__main__':
    unittest.main()
