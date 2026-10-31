"""Unit tests for the node #94 SIMD struct-copy packet.

All expectations are hand-computed from the retained instruction bytes.
No test executes the captured binary; corruption checks run in memory.
"""

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from foundation_simd_byte_reversed_copy import (  # noqa: E402
    BODY, CIE0, END, FDE, NEXT, PAD_END, PREV, START, analyze, reverse16,
    simd_copy,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-simd-byte-reversed-copy-94'
            / 'evidence.json')


def load():
    return bytearray(TARGET.read_bytes())


class SimdByteReversedCopyTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_window_bytes_and_padding(self):
        data = load()
        off = START - 0x1000
        self.assertEqual(bytes(data[off:off + 132]), BODY)
        self.assertEqual(bytes(data[off + 132:off + 144]), b'\xcc' * 12)
        self.assertEqual(bytes(data[off - 2:off]), b'\xcc' * 2)

    def test_fde_records(self):
        data = load()
        eh = 0xce1518
        self.assertEqual(bytes(data[eh:eh + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh + 0x1856f8:eh + 0x1856f8 + len(PREV)]), PREV)
        self.assertEqual(bytes(data[eh + 0x18570c:eh + 0x18570c + len(FDE)]), FDE)
        self.assertEqual(bytes(data[eh + 0x185720:eh + 0x185720 + len(NEXT)]), NEXT)

    def test_reversal_model_edges(self):
        self.assertEqual(reverse16(bytes(range(16))), bytes(range(15, -1, -1)))
        self.assertEqual(reverse16(bytes(16)), bytes(16))
        marker = bytes([0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4,
                        5, 6, 7, 8, 9, 10, 11, 12])
        self.assertEqual(reverse16(marker), marker[::-1])
        # Reversal is an involution: reversing twice restores the input.
        self.assertEqual(reverse16(reverse16(marker)), marker)

    def test_copy_rule_edges(self):
        src = bytes(range(0x34))
        out = simd_copy(src)
        self.assertEqual(out[0x00:0x10], src[0x20:0x30])
        self.assertEqual(out[0x10:0x14], src[0x30:0x34])
        self.assertEqual(out[0x14:0x24], src[0x10:0x20][::-1])
        self.assertEqual(out[0x24:0x34], src[0x00:0x10][::-1])
        # Distinct marker bytes per field.
        src = bytes([0xa0 + i for i in range(0x34)])
        out = simd_copy(src)
        self.assertEqual(out[0x14], src[0x1f])
        self.assertEqual(out[0x23], src[0x10])
        self.assertEqual(out[0x24], src[0x0f])
        self.assertEqual(out[0x33], src[0x00])
        # All-zero source stays all-zero; output length is always 0x34.
        self.assertEqual(simd_copy(bytes(0x34)), bytes(0x34))
        self.assertEqual(len(out), 0x34)

    def test_corrupt_window_byte_fails(self):
        data = load()
        data[START - 0x1000 + 0x21] ^= 0xff
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_shuffle_immediate_fails(self):
        data = load()
        data[START - 0x1000 + 0x25] = 0x00
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_padding_fails(self):
        data = load()
        data[START - 0x1000 + 132] = 0x90
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_fde_fails(self):
        data = load()
        data[0xce1518 + 0x18570c + 12] ^= 0xff
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_slot_fails(self):
        # Flip the relocation slot's addend: the slot scan must notice.
        data = load()
        secs_off = None
        # Locate .rela.dyn via the tool's section parser instead of a
        # hardcoded offset: reuse analyze's failure on a changed slot by
        # corrupting the window's own first byte is covered above, so here
        # corrupt the slot entry found through elf_index directly.
        sys.path.insert(0, str(ROOT / 'tools'))
        from elf_index import sections
        secs = sections(bytes(data))
        rela = [s for s in secs if s['name'] == '.rela.dyn'][0]
        raw = bytes(data[rela['offset']:rela['offset'] + rela['size']])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                data[rela['offset'] + off + 16] ^= 0xff
                break
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
