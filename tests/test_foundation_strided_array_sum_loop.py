"""Unit tests for the node #94 strided-array sum loop packet.

All expectations are hand-computed from the retained instruction bytes.
No test executes the captured binary; corruption checks run in memory.
"""

import hashlib
import json
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from elf_index import sections  # noqa: E402
from foundation_strided_array_sum_loop import (  # noqa: E402
    BODY, CALLER_FDES, CIE0, END, FDE, NEXT, PAD_END, START, analyze,
    element_count, strided_sum,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-strided-array-sum-loop-94'
            / 'evidence.json')


def load():
    return bytearray(TARGET.read_bytes())


def section_bytes(data, name):
    for sec in sections(bytes(data)):
        if sec['name'] == name:
            return sec
    raise AssertionError('missing section ' + name)


class StridedSumTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_rule_edges(self):
        self.assertEqual(element_count(0), 1)
        self.assertEqual(element_count(1), 2)
        self.assertEqual(element_count(0x3f), 1 << 63)
        self.assertEqual(element_count(0x40), 1)
        mem = {0x1000: 5, 0x1000 + 0xce40: 7, 0x1000 + 2 * 0xce40: 11,
               0x1008: 3, 0x1008 + 0xce40: 4}
        self.assertEqual(strided_sum(0x1000, 0, 0, mem.__getitem__), 5)
        self.assertEqual(strided_sum(0x1000, 0, 1, mem.__getitem__), 12)
        self.assertEqual(strided_sum(0x1000, 0, 2, lambda a: mem.get(a, 0)), 23)
        self.assertEqual(strided_sum(0x1000, 1, 1, mem.__getitem__), 7)
        self.assertEqual(strided_sum(0x1000, 0, 1,
                                     lambda a: (1 << 64) - 1 if a == 0x1000 else 2),
                         1)

    def test_window_bytes_and_padding(self):
        data = load()
        text = section_bytes(data, '.text')
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + 77]), BODY)
        self.assertEqual(bytes(data[off + 77:off + 78]), b'\xcc')
        self.assertEqual(bytes(data[off - 3:off]), b'\xcc' * 3)
        self.assertEqual(END - START, 77)
        self.assertEqual(PAD_END - END, 1)

    def test_fde_records(self):
        data = load()
        eh = section_bytes(data, '.eh_frame')
        self.assertEqual(bytes(data[eh['offset']:eh['offset'] + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh['offset'] + 0x2acc94:
                                 eh['offset'] + 0x2acc94 + len(FDE)]), FDE)
        self.assertEqual(bytes(data[eh['offset'] + 0x64bc40:
                                 eh['offset'] + 0x64bc40 + len(NEXT)]), NEXT)
        for offset, raw, _, _ in CALLER_FDES:
            self.assertEqual(bytes(data[eh['offset'] + offset:
                                       eh['offset'] + offset + len(raw)]), raw)

    def test_callers_stride_and_slots(self):
        result = analyze(bytes(load()))
        self.assertEqual(result['direct_callers'],
                         [0x52cfe7e, 0x52d0265, 0x52d5b03])
        self.assertEqual(result['stride_hits'], [0x52cfe2b])
        self.assertEqual(result['relocation_slots'], [])
        self.assertEqual(result['body_sha256'],
                         '38f96284a7dbdba93c5d71048539f400cc09d1363f4107b557500a9d6eb9e869')

    def test_check_reproduces_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        result = analyze(bytes(load()))
        self.assertEqual(retained['function']['start_va'], hex(START))
        self.assertEqual(retained['function']['end_va_exclusive'], hex(END))
        self.assertEqual(retained['function']['bytes'], END - START)
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(retained['function']['padding_bytes'], 1)
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(c) for c in result['direct_callers']])
        self.assertEqual(retained['incoming_pattern_scan']['relocation_slots'],
                         result['relocation_slots'])

    def test_corruption_body_fails(self):
        data = load()
        text = section_bytes(data, '.text')
        off = text['offset'] + START - text['address']
        data[off + 0x2b] ^= 0xff
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corruption_caller_fde_fails(self):
        data = load()
        eh = section_bytes(data, '.eh_frame')
        data[eh['offset'] + 0x64bd94 + 10] ^= 0xff
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
