#!/usr/bin/env python3
"""Unit tests for the node #94 bsr-derived shift-mask checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded shift-mask rule on synthetic
inputs. They never execute the captured binary, and they write no 91 MB
temporary target copies: corruption checks run in memory.
"""

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_bsr_shift_mask import (  # noqa: E402
    BODY, CALLERS, END, START, analyze, compute_shift_mask,
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


class TestBsrShiftMask(unittest.TestCase):
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
        self.assertEqual(compute_shift_mask(0), 232)
        self.assertEqual(compute_shift_mask(1), 1)
        self.assertEqual(compute_shift_mask(32), 2)
        self.assertEqual(compute_shift_mask(33), 3)
        self.assertEqual(compute_shift_mask(65), 5)
        self.assertEqual(compute_shift_mask(1 << 63), 232)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 0x41, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x2bf8c8
        data[off] = 0x00
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END + 5, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_caller_corruption_fails(self):
        data = load_bytes()
        write_va(data, 0x54c6268 + 1, b'\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_rule_monotone_spot(self):
        # Spot values hand-computed from the retained bytes, not execution:
        # rdi=2 -> doubled 3, bsr 1, shift 4, masked 0, clamped 6 -> 1.
        # rdi=64 -> doubled 127, bsr 6, shift 4, masked 3, clamped 6 -> 4.
        # rdi=128 -> doubled 255, bsr 7, shift 4, masked 3, clamped 7 -> 8.
        self.assertEqual(compute_shift_mask(2), 1)
        self.assertEqual(compute_shift_mask(64), 4)
        self.assertEqual(compute_shift_mask(128), 8)


if __name__ == '__main__':
    unittest.main()
