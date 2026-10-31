#!/usr/bin/env python3
"""Unit tests for the node #94 two-hop-field-load evidence checker.

The tests run the checker against a copy of the pinned target and against
corrupted copies, plus the decoded load rule on synthetic inputs.
They never execute the captured binary.
"""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_two_hop_field_load import (  # noqa: E402
    BODY, END, MASK, START, inspect, load,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-two-hop-field-load-94/evidence.json'


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
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(bytes(data))
        tmp.flush()
        return inspect(tmp.name)


class TestTwoHopFieldLoad(unittest.TestCase):
    def test_check_reproduces(self):
        result = inspect(str(TARGET))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(len(result['direct_callers']), 1)
        self.assertEqual(result['direct_callers'], [0x51523bc])
        self.assertEqual(result['relocation_slots'], [])

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(load({0x1008: 0x1000, 0x1000: 0x1000}, 0x1000), MASK)
        mem = {0x2008: 0x3000, 0x3000: 0x9999, 0x3008: 0x4000, 0x4010: 0x5000,
               0x5000 + 0xcb8: 42}
        self.assertEqual(load(mem, 0x2000), 42)
        mem0 = {0x2008: 0x3000, 0x3000: 0x0001, 0x3008: 0x4000, 0x4010: 0x5000,
                0x5000 + 0xcb8: 0}
        self.assertEqual(load(mem0, 0x2000), 0)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 20, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_caller_corruption_fails(self):
        data = load_bytes()
        write_va(data, 0x51523bc, b'\x90\x90\x90\x90\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x29c50c + 12
        data[off:off + 4] = (0x28).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_digest_corruption_fails(self):
        data = load_bytes()
        data[0] ^= 0xff
        with self.assertRaises(ValueError):
            check_bytes(data)


if __name__ == '__main__':
    unittest.main()
