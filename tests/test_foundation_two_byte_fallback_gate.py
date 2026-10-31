#!/usr/bin/env python3
"""Unit tests for the node #94 two-byte fallback gate evidence checker.

The tests run the checker against a copy of the pinned target and against
corrupted copies, plus the decoded two-byte fallback rule on synthetic inputs.
They never execute the captured binary. Each temporary target copy is
unlinked after use, so repeated runs do not fill /tmp with 91 MB copies.
"""

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_two_byte_fallback_gate import (  # noqa: E402
    BODY, END, SLOTS, START, inspect, parse,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-two-byte-fallback-gate-94/evidence.json'


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
    fd, tmp = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(bytes(data))
        return inspect(tmp)
    finally:
        os.unlink(tmp)


class TestTwoByteFallbackGate(unittest.TestCase):
    def test_check_reproduces(self):
        result = inspect(str(TARGET))
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
        self.assertEqual(parse(0, 0), 0)
        self.assertEqual(parse(0, 0x42), 0x42)
        self.assertEqual(parse(0x07, 0x99), 0x07)
        self.assertEqual(parse(0x42, 0), 0x42)
        self.assertEqual(parse(0xff, 0x00), 0xff)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 4, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_slot_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        rela = secs['.rela.dyn']
        # The single slot entry for this window: change its addend so the
        # slot list no longer matches.
        import struct
        raw = bytes(data[rela['offset']:rela['offset'] + rela['size']])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                data[rela['offset'] + off + 16:rela['offset'] + off + 24] = \
                    (START + 8).to_bytes(8, 'little', signed=True)
                break
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x29fe38 + 12
        data[off:off + 4] = (0x16).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_digest_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 22, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)


if __name__ == '__main__':
    unittest.main()
