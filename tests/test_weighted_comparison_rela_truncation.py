"""Synthetic-ELF tests for the weighted_comparison_static .rela.dyn guard.

Builds a minimal ELF64-LE image whose .rela.dyn lies fully inside the
file. A declared size that is not a multiple of the 24-byte RELA entry
makes the module's relocation fold (struct.iter_unpack over the section
slice in analyze) escape as a bare struct.error, which is not the
module's ValueError; rela_section must refuse it first as
ValueError ('.rela.dyn truncated'), the fail-closed shape
evm_amount_scale already applies to the same table. Whole-entry sizes
pass the guard unchanged and keep folding to the same map.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import weighted_comparison_static as subject  # noqa: E402
from elf_index import sections  # noqa: E402

ENTRY = struct.pack('<QQq', 0x5000, 8, 0x777)
SECOND = struct.pack('<QQq', 0x5800, 8, 0x888)


def build(rela_payload):
    specs = [
        (b'.text', 1, 6, 0x1000, b'\x90' * 16),
        (b'.rela.dyn', 4, 3, 0x4000, rela_payload),
        (b'.shstrtab', 3, 0, 0, None),
    ]
    shstr = b'\x00'
    name_off = {}
    for name, *_ in specs:
        name_off[name] = len(shstr)
        shstr += name + b'\x00'
    specs[2] = (b'.shstrtab', 3, 0, 0, shstr)
    count = 1 + len(specs)
    shoff = 64
    blob = bytearray(b'\x00' * (64 + 64 * count))
    laid = []
    for name, typ, flags, addr, payload in specs:
        off = len(blob)
        blob += payload
        laid.append((name_off[name], typ, flags, addr, off, len(payload)))
    for i, row in enumerate(laid):
        struct.pack_into('<IIQQQQIIQQ', blob, shoff + 64 * (i + 1),
                         row[0], row[1], row[2], row[3], row[4], row[5],
                         0, 0, 1, 0)
    blob[0:16] = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8
    struct.pack_into('<HHIQQQIHHHHHH', blob, 16,
                     2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, count, 3)
    return bytes(blob)


class WeightedComparisonRelaTruncationTests(unittest.TestCase):
    def test_partial_entry_fails_closed(self):
        # On base the fold over this section escapes as struct.error,
        # which is not a ValueError (probe-verified census).
        with self.assertRaisesRegex(ValueError, '.rela.dyn truncated'):
            subject.rela_section(build(ENTRY + b'\x00'))

    def test_wellformed_sizes_pass_and_fold_unchanged(self):
        for payload, size in [(ENTRY, 24), (ENTRY + SECOND, 48)]:
            data = build(payload)
            sec = subject.rela_section(data)
            self.assertEqual(sec['size'], size)
            folded = {a: (i, v) for a, i, v in struct.iter_unpack(
                '<QQq', data[sec['offset']:sec['offset'] + sec['size']])}
            self.assertEqual(folded[0x5000], (8, 0x777))
            self.assertEqual(len(folded), size // 24)
            via_index = next(s for s in sections(data)
                             if s['name'] == '.rela.dyn')
            self.assertEqual(sec, via_index)


if __name__ == '__main__':
    unittest.main()
