"""Synthetic-ELF tests for scratch_pair_static.relocations fail-closed checks.

Builds a minimal ELF64-LE image with a .rela.dyn section, mirroring
tools/scratch_pair_static.py::relocations. No materialized node115
binary is needed: the existing test_scratch_pair_static.py skips
without one, so these cases run offline on synthetic input.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import scratch_pair_static as subject


def build(rela=b'', include_rela=True, duplicate=False):
    names = b'\x00.shstrtab\x00.rela.dyn\x00'
    shstr_off, rela_off = 0x100, 0x200
    shoff = 0x500

    def sh(name_off, typ, off, size):
        return struct.pack('<IIQQQQIIQQ', name_off, typ, 0, 0, off, size, 0, 0, 1, 0)

    rows = [sh(0, 0, 0, 0),
            sh(names.index(b'.shstrtab'), 3, shstr_off, len(names))]
    if include_rela:
        rows.append(sh(names.index(b'.rela.dyn'), 4, rela_off, len(rela)))
    if duplicate:
        rows.append(sh(names.index(b'.rela.dyn'), 4, rela_off, len(rela)))
    data = bytearray(shoff + len(rows) * 64)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, len(rows), 1)
    data[shstr_off:shstr_off + len(names)] = names
    data[rela_off:rela_off + len(rela)] = rela
    for i, row in enumerate(rows):
        data[shoff + i * 64:shoff + (i + 1) * 64] = row
    return bytes(data)


VALID = struct.pack('<QQq', 0x64e0918, 8, subject.ACCESSOR)


class ScratchPairRelocationsFailClosedTests(unittest.TestCase):
    def test_valid_rela_dyn_unchanged(self):
        by_offset, hits = subject.relocations(build(VALID))
        self.assertEqual(by_offset[0x64e0918], [(8, subject.ACCESSOR)])
        self.assertEqual(hits, [0x64e0918])

    def test_missing_rela_dyn_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'exactly one .rela.dyn'):
            subject.relocations(build(include_rela=False))

    def test_duplicate_rela_dyn_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'exactly one .rela.dyn'):
            subject.relocations(build(VALID, duplicate=True))

    def test_truncated_rela_dyn_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'multiple of 24'):
            subject.relocations(build(VALID + b'\x00'))


if __name__ == '__main__':
    unittest.main()
