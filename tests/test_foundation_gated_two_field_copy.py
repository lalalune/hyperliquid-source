#!/usr/bin/env python3
"""Unit tests for the node #94 gated two-field copy evidence checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded gated two-field copy rule on
synthetic inputs. They never execute the captured binary, and they write no
91 MB temporary target copies: corruption checks run in memory.
"""

import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_gated_two_field_copy import (  # noqa: E402
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


class TestGatedTwoFieldCopy(unittest.TestCase):
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
        self.assertIsNone(parse(True, 1, 0x11, 0x22))
        self.assertIsNone(parse(False, 0, 0x11, 0x22))
        self.assertEqual(parse(False, 1, 0x11, 0x22), (0x11, 0x22))
        self.assertEqual(parse(False, 1, 0x0, 0xffffffffffffffff),
                         (0x0, 0xffffffffffffffff))
        self.assertEqual(parse(False, 0xff, 0x22, 0x11), (0x22, 0x11))

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
        secs = sections_of(data)
        rela = secs['.rela.dyn']
        # The single slot entry for this window: change its addend so the
        # slot list no longer matches.
        raw = bytes(data[rela['offset']:rela['offset'] + rela['size']])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                data[rela['offset'] + off + 16:rela['offset'] + off + 24] = \
                    (START + 8).to_bytes(8, 'little', signed=True)
                break
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x2b5864 + 12
        data[off:off + 4] = (0x2b).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_digest_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 41, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
