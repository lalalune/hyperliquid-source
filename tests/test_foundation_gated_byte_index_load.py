#!/usr/bin/env python3
"""Unit tests for the node #94 gated byte-index load checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded byte rule on synthetic inputs.
They never execute the captured binary, and they write no 91 MB temporary
target copies: corruption checks run in memory.
"""

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_gated_byte_index_load import (  # noqa: E402
    BODY, CALLERS, END, START, analyze, select_byte,
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


class TestGatedByteIndexLoad(unittest.TestCase):
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
        table = {0x1000 + i: i & 0xff for i in range(256)}
        self.assertEqual(select_byte(0, 0x00, 5, 3, 0, 0x1010, 0x1000, 0x77, table), 0)
        self.assertEqual(select_byte(1, 0x00, 5, 4, 0, 0x1010, 0x1000, 0x77, table), 0)
        self.assertEqual(select_byte(1, 0x00, 5, 3, 0, 0x1010, 0x1000, 0x77, table), 0x04)
        self.assertEqual(select_byte(1, 0xff, 5, 99, 0, 0x1010, 0x1000, 0x77, table), 0x0f)
        self.assertEqual(select_byte(1, 0x00, 5, 3, 0, 0x1000, 0x1000, 0x77, table), 0x77)
        self.assertEqual(select_byte(1, 0x00, 5, 0, 0, 0x1010, 0x1000, 0x77, table), 0x00)
        self.assertEqual(select_byte(1, 0x00, 5, 3, 90, 0x1010, 0x1000, 0x77, table), 0x00)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 0x20, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x28f740
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
        write_va(data, 0x5002807 + 1, b'\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_branch_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 0x0b, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))
