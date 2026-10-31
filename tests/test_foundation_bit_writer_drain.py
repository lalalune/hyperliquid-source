#!/usr/bin/env python3
"""Unit tests for the node #94 bit-writer drain evidence checker.

The tests run the checker against a copy of the pinned target and against
corrupted copies, plus the decoded drain rule on synthetic inputs.
They never execute the captured binary. Each temporary target copy is
unlinked after use, so repeated runs do not fill /tmp with 91 MB copies.
"""

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_bit_writer_drain import (  # noqa: E402
    BODY, CALL_SITES, END, START, drain, inspect,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-bit-writer-drain-94/evidence.json'


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


def check_bytes(data):
    fd, tmp = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(bytes(data))
        return inspect(tmp)
    finally:
        os.unlink(tmp)


class TestBitWriterDrain(unittest.TestCase):
    def test_check_reproduces(self):
        result = inspect(str(TARGET))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['direct_callers'],
                         [site for site, _ in CALL_SITES])
        self.assertEqual(len(result['direct_callers']), 26)
        self.assertEqual(result['relocation_slots'], [])

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(drain(16, 0xabcd, 5), (bytes([0xcd, 0xab]), 0, 0, 7))
        self.assertEqual(drain(16, 0x0000, 0), (bytes([0, 0]), 0, 0, 2))
        self.assertEqual(drain(8, 0x1234, 3), (bytes([0x34]), 0, 0x12, 4))
        self.assertEqual(drain(15, 0x00ff, 9), (bytes([0xff]), 7, 0x00, 10))
        self.assertEqual(drain(9, 0x8001, 0), (bytes([0x01]), 1, 0x80, 1))
        self.assertEqual(drain(7, 0xffff, 4), (b'', 7, 0xffff, 4))
        self.assertEqual(drain(0, 0x1234, 4), (b'', 0, 0x1234, 4))
        self.assertEqual(drain(-1, 0x1234, 4), (b'', -1, 0x1234, 4))
        self.assertEqual(drain(17, 0x1234, 3), (bytes([0x34]), 9, 0x12, 4))

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 10, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_caller_corruption_fails(self):
        data = load_bytes()
        write_va(data, CALL_SITES[0][0], b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x2bf2a8 + 12
        data[off:off + 4] = (0x87).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_digest_corruption_fails(self):
        data = load_bytes()
        data[0] ^= 0xff
        with self.assertRaises(ValueError):
            check_bytes(data)


if __name__ == '__main__':
    unittest.main()
