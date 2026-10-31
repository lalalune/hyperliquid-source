#!/usr/bin/env python3
"""Unit tests for the node #94 divide-then-log2 bucket evidence checker.

The tests run the checker against the pinned target and against corrupted
in-memory copies, plus the decoded bucket rule on synthetic inputs. They
never execute the captured binary and never write a 91 MB temporary target
copy, so repeated runs do not fill /tmp.
"""

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_divide_then_log2_bucket import (  # noqa: E402
    BODY, CALL_BYTES, CALL_SITE, END, PAD_END, START, analyze, parse,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-divide-then-log2-bucket-94/evidence.json'


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


class TestDivideThenLog2Bucket(unittest.TestCase):
    def test_check_reproduces(self):
        result = analyze(TARGET.read_bytes())
        self.assertEqual(result['body_sha256'],
                         '6a5f51de0418a80d23313f6f8c849a6058bff5676858fa9a292cd9266b5b5011')
        self.assertEqual(result['direct_callers'], [CALL_SITE])
        self.assertEqual(result['relocation_slots'], [])
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(CALL_SITE)])

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_window_corruption(self):
        data = load_bytes()
        write_va(data, START + 0x38, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_padding_corruption(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x28ac3c + 12
        data[off:off + 4] = struct.pack('<I', 0x73)
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_caller_corruption(self):
        data = load_bytes()
        write_va(data, CALL_SITE, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_rule_edges(self):
        self.assertEqual(parse(0, 7), 0)
        self.assertEqual(parse(1, 1), 0)
        self.assertEqual(parse(2, 1), 1)
        self.assertEqual(parse(3, 1), 1)
        self.assertEqual(parse(4, 1), 2)
        self.assertEqual(parse(7, 1), 2)
        self.assertEqual(parse(8, 1), 3)
        self.assertEqual(parse(15, 1), 3)
        self.assertEqual(parse(16, 1), 4)
        self.assertEqual(parse(31, 1), 4)
        self.assertEqual(parse(32, 1), 5)
        self.assertEqual(parse(63, 1), 5)
        self.assertEqual(parse(64, 1), 6)
        self.assertEqual(parse(2 ** 63, 1), 6)
        self.assertEqual(parse(2 ** 64 - 1, 1), 6)
        self.assertEqual(parse(100, 7), 3)
        with self.assertRaises(ValueError):
            parse(100, 0)


if __name__ == '__main__':
    unittest.main()
