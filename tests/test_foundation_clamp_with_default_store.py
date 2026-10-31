#!/usr/bin/env python3
"""Unit tests for the node #94 clamp-with-default store checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded clamp rule on synthetic inputs.
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

from foundation_clamp_with_default_store import (  # noqa: E402
    BODY, CALLERS, END, START, analyze, clamp_store,
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


class TestClampWithDefaultStore(unittest.TestCase):
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
        self.assertEqual(clamp_store(0), 9)
        self.assertEqual(clamp_store(-1), 9)
        self.assertEqual(clamp_store(-0x80000000), 9)
        self.assertEqual(clamp_store(1), 1)
        self.assertEqual(clamp_store(12), 12)
        self.assertEqual(clamp_store(13), 12)
        self.assertEqual(clamp_store(0x7fffffff), 12)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 0x09, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x2be8fc
        data[off] = 0x00
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_caller_call_bytes(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        for site in CALLERS:
            off = text['offset'] + site - text['address']
            self.assertEqual(data[off], 0xe8)
            rel = struct.unpack_from('<i', data, off + 1)[0]
            self.assertEqual(site + 5 + rel, START)

    def test_relocation_scan_empty(self):
        data = load_bytes()
        secs = sections_of(data)
        naming = []
        for s in secs.values():
            if s['name'].startswith('.rela.') and s['size'] % 24 == 0:
                raw = bytes(data[s['offset']:s['offset'] + s['size']])
                for off in range(0, len(raw), 24):
                    address, info, addend = struct.unpack_from('<QQq', raw, off)
                    if addend == START:
                        naming.append((s['name'], address))
        self.assertEqual(naming, [])

    def test_next_fde_adjacent(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x2be910
        record = bytes(data[off:off + 28])
        pc = eh['address'] + 0x2be910 + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        self.assertEqual(pc, END)
        self.assertEqual(pc + extent, 0x5488d4e)


if __name__ == '__main__':
    unittest.main()
