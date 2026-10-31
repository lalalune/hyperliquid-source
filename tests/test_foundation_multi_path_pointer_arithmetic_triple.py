#!/usr/bin/env python3
"""Unit tests for the node #94 multi-path pointer-arithmetic triple checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded triple rule on synthetic inputs.
They never execute the captured binary, and they write no 91 MB temporary
target copies: corruption checks run in memory.
"""

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_multi_path_pointer_arithmetic_triple import (  # noqa: E402
    BODY, END, MASK, SLOTS, START, analyze, triple,
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


class TestMultiPathPointerArithmeticTriple(unittest.TestCase):
    def test_check_reproduces(self):
        result = analyze(bytes(load_bytes()))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['direct_callers'], [])
        self.assertEqual([addr for _, addr in result['relocation_slots']], SLOTS)
        self.assertEqual(len(SLOTS), 1)

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        base = {0x240: 1, 0x308: 0x5000, 0x310: 0x6000,
                0xa0: 0, 0xa8: 0, 0xd8: 0, 0x300: 0}
        self.assertEqual(triple(base), (0x5000, 0x6000))
        computed = {0x240: 0, 0xa0: 0x1000, 0xa8: 0x100, 0xd8: 0,
                    0x300: 0x40, 0x308: 0, 0x310: 0}
        self.assertEqual(triple(computed), (0x10b8, 0x40))
        no_adjust = {**computed, 0xd8: 5}
        self.assertEqual(triple(no_adjust), (0x10c0, 0x40))
        flag_other = {**computed, 0x240: 2, 0x308: 0x5000, 0x310: 0x6000}
        self.assertEqual(triple(flag_other), (0x10b8, 0x40))
        wrapped = {0x240: 0, 0xa0: 0x10, 0xa8: 0x8, 0xd8: 0,
                   0x300: 0x40, 0x308: 0, 0x310: 0}
        self.assertEqual(triple(wrapped), ((0x10 - 0x40) & MASK, 0x40))

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
        write_va(data, START + 11, b'\x74\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_join_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 60, b'\xeb\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_slot_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        rela = secs['.rela.dyn']
        raw = bytes(data[rela['offset']:rela['offset'] + rela['size']])
        import struct
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                data[rela['offset'] + off + 16:rela['offset'] + off + 24] = \
                    struct.pack('<q', START + 8)
                break
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
