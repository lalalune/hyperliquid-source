#!/usr/bin/env python3
"""Unit tests for the node #94 hash-bit-probe-loop evidence checker.

The tests run the checker against a copy of the pinned target and against
corrupted copies, plus the decoded probe rule on synthetic tables.
They never execute the captured binary.
"""

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_hash_bit_probe_loop import (  # noqa: E402
    BODY, CIE0, END, FDE, NEXT, PAD_END, START, block_offset, inspect,
    probe_all,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-hash-bit-probe-loop-94/evidence.json'


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


class TestHashBitProbeLoop(unittest.TestCase):
    def test_check_reproduces(self):
        result = inspect(str(TARGET))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['padding_bytes'], 13)
        self.assertEqual(result['direct_callers'], [])
        self.assertEqual(result['relocation_slots'],
                         [('.rela.dyn', 0x5763838, 8)])
        self.assertEqual(result['fde'], (START, 0x83))
        self.assertEqual(result['next_fde'], (PAD_END, 0x11))

    def test_body_hash(self):
        data = load()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)
        self.assertTrue(all(b == 0xCC for b in
                            data[off + len(BODY):off + (PAD_END - START)]))

    def test_fde_bytes(self):
        data = load()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        self.assertEqual(bytes(data[eh['offset']:eh['offset'] + len(CIE0)]),
                         CIE0)
        self.assertEqual(bytes(data[eh['offset'] + 0x2B38D0:
                                  eh['offset'] + 0x2B38D0 + 16]), FDE)
        self.assertEqual(bytes(data[eh['offset'] + 0x2B38E4:
                                  eh['offset'] + 0x2B38E4 + 16]), NEXT)

    def test_rule_edges(self):
        # All-set block, any count -> 1; all-clear block -> 0 at once.
        self.assertEqual(probe_all(bytes(64), 0, 0x12345678 << 32, 3), 0)
        self.assertEqual(probe_all(bytes([0xFF] * 64), 0,
                                   0x12345678 << 32, 3), 1)
        # Non-positive counts never probe: even an empty table is fine.
        self.assertEqual(probe_all(bytes(0), 0, 0x12345678 << 32, 0), 1)
        self.assertEqual(probe_all(bytes(0), 0, 0x12345678 << 32, -5), 1)
        # First probe of key high 0x80000000: byte index 32, bit 0.
        table = bytearray(64)
        table[32] = 0x01
        self.assertEqual(probe_all(bytes(table), 0, 0x80000000 << 32, 1), 1)
        table[32] = 0x02
        self.assertEqual(probe_all(bytes(table), 0, 0x80000000 << 32, 1), 0)
        # Second probe value is high * 0x9e3779b9 mod 2^32.
        high = 0x00000001
        second = (high * 0x9E3779B9) & 0xFFFFFFFF
        table = bytearray(64)
        table[high >> 26] |= 1 << ((high >> 23) & 7)
        table[second >> 26] |= 1 << ((second >> 23) & 7)
        self.assertEqual(probe_all(bytes(table), 0, high << 32, 2), 1)
        table[second >> 26] &= ~(1 << ((second >> 23) & 7))
        self.assertEqual(probe_all(bytes(table), 0, high << 32, 2), 0)

    def test_block_offset(self):
        # field>>6 == 0 -> offset 0 regardless of key.
        self.assertEqual(block_offset(0x3F, 0xDEADBEEFCAFEBABE), 0)
        # ((64 * 2^32) >> 32) << 6 = 64 << 6 = 4096.
        self.assertEqual(block_offset(64 << 6, 0x00000001_00000000), 4096)
        # Result is always a multiple of 64.
        for field, key in [(123456, 0x9E3779B97F4A7C15),
                           (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)]:
            self.assertEqual(block_offset(field, key) % 64, 0)

    def test_corrupt_body_fails(self):
        data = load()
        write_va(data, START + 10, b'\x90')
        tmp = ROOT / 'work' / 'test-corrupt-target'
        tmp.parent.mkdir(exist_ok=True)
        tmp.write_bytes(bytes(data))
        try:
            with self.assertRaises(ValueError):
                inspect(str(tmp))
        finally:
            tmp.unlink(missing_ok=True)

    def test_corrupt_pad_fails(self):
        data = load()
        write_va(data, END + 3, b'\x90')
        tmp = ROOT / 'work' / 'test-corrupt-pad'
        tmp.parent.mkdir(exist_ok=True)
        tmp.write_bytes(bytes(data))
        try:
            with self.assertRaises(ValueError):
                inspect(str(tmp))
        finally:
            tmp.unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
