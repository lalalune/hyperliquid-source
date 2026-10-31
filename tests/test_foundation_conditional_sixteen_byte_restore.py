#!/usr/bin/env python3
"""Unit tests for the node #94 conditional 16-byte restore checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded restore rule on synthetic inputs.
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

from foundation_conditional_sixteen_byte_restore import (  # noqa: E402
    BODY, END, PAD_END, SLOT, START, analyze, restore_path,
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


class TestConditionalSixteenByteRestore(unittest.TestCase):
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
        self.assertEqual(restore_path(0x10), 'qword')
        self.assertEqual(restore_path(0x16), 'qword')
        self.assertEqual(restore_path(0x17), 'none')
        self.assertEqual(restore_path(0x0f), 'none')
        self.assertEqual(restore_path(0x00), 'full')
        self.assertEqual(restore_path(0x04), 'full')
        self.assertEqual(restore_path(0x05), 'none')
        self.assertEqual(restore_path(0xff), 'none')

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 0x47, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x2788bc
        data[off + 12:off + 16] = struct.pack('<I', 0x63)
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_slot_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        rela = secs['.rela.dyn']
        raw = bytes(data[rela['offset']:rela['offset'] + rela['size']])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START and address == SLOT:
                data[rela['offset'] + off + 16:rela['offset'] + off + 24] = \
                    struct.pack('<q', START + 8)
                break
        else:
            self.fail('relocation slot entry not found')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_incoming_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        # Forge a direct e8 site in .text whose rel32 lands on START.
        site = text['address'] + 0x1000
        rel = START - (site + 5)
        write_va(data, site, b'\xe8' + struct.pack('<i', rel))
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
