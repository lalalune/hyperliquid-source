#!/usr/bin/env python3
"""Unit tests for the node #94 multiply-xor mixer-loop evidence checker.

The tests run the checker against a copy of the pinned target and against
corrupted copies, plus the decoded fold rule on synthetic inputs.
They never execute the captured binary.
"""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_multiply_xor_mixer_loop import (  # noqa: E402
    BODY, END, MASK, START, inspect, mix, qwords,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-multiply-xor-mixer-loop-94/evidence.json'


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
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(bytes(data))
        tmp.flush()
        return inspect(tmp.name)


class TestMultiplyXorMixerLoop(unittest.TestCase):
    def test_check_reproduces(self):
        result = inspect(str(TARGET))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['direct_callers'], [])
        self.assertEqual(result['relocation_slots'],
                         [['.rela.dyn', '0x57709e8']])

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(mix(b'', 0x1000, 0, 0x2222, 0x1111, 0), 0x3333)
        self.assertEqual(mix(bytes(5), 0x1000, 5, 0x2222, 0x1111, 0), 0x3333)
        self.assertEqual(mix(qwords(1, 2), 0x1000, 16, 5, 3, 0), 6)
        self.assertEqual(mix(qwords(1, 2, 3, 4), 0x1000, 32, 5, 3, 0), 8)
        self.assertEqual(mix(qwords(1, 2, 3, 4, 5, 6), 0x1000, 48, 5, 3, 0), 77)
        self.assertEqual(mix(qwords(0, 3), 0x1000, 16, 0, MASK, 0), MASK - 9)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 53, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_relocation_corruption_fails(self):
        import struct
        data = load_bytes()
        secs = sections_of(data)
        dyn = secs['.rela.dyn']
        raw = bytes(data[dyn['offset']:dyn['offset'] + dyn['size']])
        for off in range(0, len(raw), 24):
            address, _info, _addend = struct.unpack_from('<QQq', raw, off)
            if address == 0x57709e8:
                data[dyn['offset'] + off:dyn['offset'] + off + 8] = \
                    (0x57709e9).to_bytes(8, 'little')
                break
        else:
            self.fail('naming relocation slot not found')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x20bf4 + 12
        data[off:off + 4] = (0x67).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_digest_corruption_fails(self):
        data = load_bytes()
        data[0] ^= 0xff
        with self.assertRaises(ValueError):
            check_bytes(data)


if __name__ == '__main__':
    unittest.main()
