#!/usr/bin/env python3
"""Unit tests for the node #94 threshold table-pointer select checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded select rule on synthetic inputs.
They never execute the captured binary, and they write no 91 MB temporary
target copies: corruption checks run in memory.
"""

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_threshold_table_pointer_select import (  # noqa: E402
    BODY, END, PAD_END, SLOT, START, TABLE_ADDRESS, analyze, select_rule,
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


class TestThresholdTablePointerSelect(unittest.TestCase):
    def test_check_reproduces(self):
        result = analyze(bytes(load_bytes()))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['direct_callers'], [])
        self.assertEqual(result['relocation_slots'], [['.rela.dyn', hex(SLOT)]])

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(select_rule(0x00), TABLE_ADDRESS)
        self.assertEqual(select_rule(0x3f), TABLE_ADDRESS)
        self.assertEqual(select_rule(0x40), 0)
        self.assertEqual(select_rule(0xffffffffffffffff), 0)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 0x04, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x2c175c
        data[off + 12] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_slot_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        rela = secs['.rela.dyn']
        off = rela['offset']
        raw = bytes(data[off:off + rela['size']])
        import struct
        for pos in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, pos)
            if addend == START:
                data[off + pos + 16:off + pos + 24] = struct.pack('<q', START + 8)
                break
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_incoming_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        # Plant an e8 site in .text whose rel32 lands on the window start.
        # The first bytes of .text are not part of any claimed window; the
        # checker must reject the planted caller.
        import struct
        site_va = text['address']
        rel = START - (site_va + 5)
        off = text['offset']
        data[off] = 0xe8
        data[off + 1:off + 5] = struct.pack('<i', rel)
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
