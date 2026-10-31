#!/usr/bin/env python3
"""Unit tests for the node #94 keyed multiply-xor mixer evidence checker.

The tests run the checker against the pinned target and against corrupted
in-memory copies, plus the decoded keyed multiply-xor rule on synthetic
inputs. They never execute the captured binary and never write a 91 MB
temporary target copy, so repeated runs do not fill /tmp.
"""

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_keyed_multiply_xor_mixer import (  # noqa: E402
    BODY, END, KEYPTR, PAD_END, START, analyze, parse,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-keyed-multiply-xor-mixer-94/evidence.json'


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


class TestKeyedMultiplyXorMixer(unittest.TestCase):
    def test_check_reproduces(self):
        body = analyze(TARGET.read_bytes())
        self.assertEqual(body, BODY)
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         '03a9ea4d6ef3a449f21050b721a7fcef1115ad7953ee29683b7889948067b492')

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(parse(0, bytes(20), 0, 0), 0)
        self.assertEqual(parse(0, bytes(20), 1, 0), 0x14)
        self.assertEqual(parse(0, bytes(20), 0, 0xffffffffffffffff), 0)
        # The 20-byte span matters: bytes 16..19 feed the qword at rsi+12,
        # so changing them changes the result.
        self.assertNotEqual(
            parse(0, bytes.fromhex('000102030405060708090a0b0c0d0e0f10111213'),
                  0x9e3779b97f4a7c15, 0xdeadbeefcafebabe),
            parse(0, bytes.fromhex('000102030405060708090a0b0c0d0e0f00000000'),
                  0x9e3779b97f4a7c15, 0xdeadbeefcafebabe))
        # Emulator vectors recorded in evidence.json replay exactly.
        evidence = json.loads(EVIDENCE.read_text())
        self.assertEqual(len(evidence['emulator_vectors']), 8)
        for vector in evidence['emulator_vectors']:
            self.assertEqual(
                parse(int(vector['rdi_qword'], 16),
                      bytes.fromhex(vector['input_block_hex']),
                      int(vector['k0'], 16), int(vector['k1'], 16)),
                int(vector['result'], 16))
        self.assertEqual(evidence['emulator_sweep']['cases'], 5680)
        self.assertEqual(evidence['emulator_sweep']['mismatches'], 0)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 10, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x19332c + 12
        data[off:off + 4] = (0x45).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_caller_corruption_fails(self):
        data = load_bytes()
        write_va(data, 0x32ad5f3, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_naming_relocation_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        rela = secs['.rela.dyn']
        # Point one relocation entry's addend at this window so the
        # zero-naming-relocation lock no longer holds.
        data[rela['offset'] + 16:rela['offset'] + 24] = \
            START.to_bytes(8, 'little', signed=True)
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_keyptr_target(self):
        # The rip-relative displacement in the body resolves into .got.
        disp = struct.unpack_from('<i', BODY, 3)[0]
        self.assertEqual(START + 7 + disp, KEYPTR)


if __name__ == '__main__':
    unittest.main()
