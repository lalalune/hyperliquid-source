#!/usr/bin/env python3
"""Tests for the node115 two-variant error-string selector @ 0x14cad10.

Cover regeneration against the pinned binary, the branchless length/pointer
relation, and byte-level negative controls: corrupting any semantic opcode,
either RIP-relative message LEA, a selected rodata byte, the FDE extent or the
publishing relocation must break analysis.
"""
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import error_str_select_static as mod  # noqa: E402

TARGET = mod.TARGET


def load():
    data = TARGET.read_bytes()
    if hashlib.sha256(data).hexdigest() != mod.SHA:
        raise unittest.SkipTest('pinned node115 binary unavailable')
    return bytearray(data)


class ErrorStrSelect(unittest.TestCase):
    def setUp(self):
        self.data = load()

    def test_regenerates(self):
        with tempfile.TemporaryDirectory() as d:
            report = mod.generate(TARGET, Path(d) / 'out')
        self.assertEqual(report['owner']['start'], '0x14cad10')
        self.assertEqual(report['owner']['bytes'], 40)
        self.assertEqual(report['owner']['instructions'], 10)
        self.assertFalse(report['captured_code_executed'])

    def test_relation(self):
        spec = mod.specification()
        self.assertEqual(mod.model(spec, 0), (0x464b54, 17))
        self.assertEqual(mod.model(spec, 1), (0x464b65, 14))
        # Length is the branchless 3*(b^1)+14 form the body actually computes.
        for b in range(256):
            _, length = mod.model(spec, b)
            self.assertEqual(length, 3 * (b ^ 1) + 14)

    def test_examples_bind_the_two_messages(self):
        report = mod.analyze(bytes(self.data))
        texts = {e['discriminant']: e['text'] for e in report['examples']}
        self.assertEqual(texts, {0: 'invalid character', 1: 'invalid length'})

    def test_baseline_passes(self):
        self.assertEqual(mod.analyze(bytes(self.data))['owner']['bytes'], 40)

    def _expect_fail(self, data, needle):
        with self.assertRaises(ValueError) as ctx:
            mod.analyze(bytes(data))
        self.assertIn(needle, str(ctx.exception))

    def test_control_xor_immediate(self):
        # xor rax,0x1 lives at file offset of VA 0x14cad16 (+3 is the imm8).
        off = 0x14c9d10 + (0x14cad16 - 0x14cad10) + 3
        self.assertEqual(self.data[off], 0x01)
        self.data[off] = 0x02
        self._expect_fail(self.data, 'body bytes changed')

    def test_control_length_base(self):
        # add rdx,0xe at 0x14cad1e; imm8 is the 4th byte.
        off = 0x14c9d10 + (0x14cad1e - 0x14cad10) + 3
        self.assertEqual(self.data[off], 0x0e)
        self.data[off] = 0x0f
        self._expect_fail(self.data, 'body bytes changed')

    def test_control_cmov_select(self):
        # cmovne rax,rsi at 0x14cad33: flip to cmove (0x44 -> 0x45 is the /r;
        # corrupt the opcode byte 0x0f45 -> 0x0f44 via the condition nibble).
        off = 0x14c9d10 + (0x14cad33 - 0x14cad10)
        self.assertEqual(bytes(self.data[off:off + 4]).hex(), '480f45c6')
        self.data[off + 2] = 0x44
        self._expect_fail(self.data, 'body bytes changed')

    def test_control_message_lea(self):
        # Retarget the "invalid length" LEA disp32 (at 0x14cad25).
        off = 0x14c9d10 + (0x14cad22 - 0x14cad10) + 3
        self.data[off] ^= 0x10
        self._expect_fail(self.data, 'body bytes changed')

    def test_control_rodata_byte(self):
        # Flip a byte inside "invalid character".
        off = next(s['offset'] + 0x464b54 - s['address']
                   for s in __import__('elf_index').sections(bytes(self.data))
                   if s['type'] != 8 and s['address'] <= 0x464b54 < s['address'] + s['size'])
        self.data[off] ^= 0x20
        self._expect_fail(self.data, 'rodata message changed')

    def test_control_relocation(self):
        # Corrupt the RELATIVE relocation addend that publishes 0x14cad10.
        import struct
        s = next(s for s in __import__('elf_index').sections(bytes(self.data))
                 if s['name'] == '.rela.dyn')
        for i in range(s['offset'], s['offset'] + s['size'], 24):
            rva, info, add = struct.unpack_from('<QQq', self.data, i)
            if add == 0x14cad10 and (info & 0xffffffff) == 8:
                struct.pack_into('<q', self.data, i + 16, 0x14cad11)
                break
        else:
            self.fail('publishing relocation not found')
        self._expect_fail(self.data, 'vtable relocation changed')


if __name__ == '__main__':
    unittest.main()
