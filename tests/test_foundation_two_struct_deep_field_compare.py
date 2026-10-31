#!/usr/bin/env python3
"""Unit tests for the node #94 two-struct deep-field compare evidence checker.

The tests run the checker against the pinned target and against corrupted
in-memory copies, plus the decoded compare rule on synthetic inputs. They
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

from foundation_two_struct_deep_field_compare import (  # noqa: E402
    BODY, CALL_BYTES, CALL_SITE, END, PAD_END, START, analyze, parse,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-two-struct-deep-field-compare-94/evidence.json'


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


class TestTwoStructDeepFieldCompare(unittest.TestCase):
    def test_check_reproduces(self):
        result = analyze(TARGET.read_bytes())
        self.assertEqual(result['body_sha256'],
                         'ba01a0bc0b332ab68baefbed1a8d6882f4170d1f086235c4b08339f2bc0ae0fd')
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
        write_va(data, START + 12, b'\x90')
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
        off = eh['offset'] + 0x29ff20 + 12
        data[off] = 0x19  # FDE range 24 -> 25
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_caller_call_corruption(self):
        data = load_bytes()
        write_va(data, CALL_SITE, b'\x90' + CALL_BYTES[1:])
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_rule_edges(self):
        self.assertEqual(parse(0, 0), 0)
        self.assertEqual(parse(1, 0), 1)
        self.assertEqual(parse(0, 1), 0)
        self.assertEqual(parse(0xffffffffffffffff, 0xfffffffffffffffe), 1)
        self.assertEqual(parse(0, 0xffffffffffffffff), 0)
        self.assertEqual(parse(0x8000000000000000, 0x7fffffffffffffff), 1)

    def test_no_calls_inside_window(self):
        self.assertNotIn(b'\xe8', BODY)
        self.assertEqual(PAD_END - END, 8)


if __name__ == '__main__':
    unittest.main()
