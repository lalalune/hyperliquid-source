#!/usr/bin/env python3
"""Unit tests for the node #94 gated byte test evidence checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded gated byte test rule on
synthetic inputs. They never execute the captured binary, and they write no
91 MB temporary target copies: corruption checks run in memory.
"""

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_gated_byte_test import (  # noqa: E402
    BODY, END, SLOTS, START, analyze, parse,
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


class TestGatedByteTest(unittest.TestCase):
    def test_check_reproduces(self):
        result = analyze(bytes(load_bytes()))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['direct_callers'], [])
        self.assertEqual([addr for _, addr in result['relocation_slots']], SLOTS)

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(parse(True, 0), 0)
        self.assertEqual(parse(True, 1), 0)
        self.assertEqual(parse(False, 0), 1)
        self.assertEqual(parse(False, 1), 0)
        self.assertEqual(parse(False, 0xff), 0)

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

    def test_slot_corruption_fails(self):
        data = load_bytes()
        # Rewrite the first relocation slot's addend to a different window.
        secs = sections_of(data)
        rela = secs['.rela.dyn']
        import struct
        raw = bytes(data[rela['offset']:rela['offset'] + rela['size']])
        found = None
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START and address == int(SLOTS[0], 16):
                found = rela['offset'] + off + 16
                break
        self.assertIsNotNone(found)
        data[found:found + 8] = struct.pack('<q', START + 0x10)
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_branch_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 15, b'\x0b')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_gate_compare_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 18, b'\xb9')
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
