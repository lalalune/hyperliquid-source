"""Unit tests for the node #94 case-insensitive 3-byte equality packet.

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
from foundation_case_insensitive_3byte_equality import (  # noqa: E402
    BODY, CALLER_FDES, CIE0, END, FDE, NEXT, PAD_END, START, analyze,
    case_insensitive_3byte_equal, fold,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-case-insensitive-3byte-equality-94'
            / 'evidence.json')


def load():
    return bytearray(TARGET.read_bytes())


def section_bytes(data, name):
    for sec in sections(bytes(data)):
        if sec['name'] == name:
            return sec
    raise AssertionError('missing section ' + name)


class CaseInsensitive3ByteEqualityTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_rule_edges(self):
        self.assertEqual(fold(0x41), 0x61)
        self.assertEqual(fold(0x5a), 0x7a)
        self.assertEqual(fold(0x40), 0x40)
        self.assertEqual(fold(0x5b), 0x5b)
        self.assertEqual(fold(0x00), 0x00)
        self.assertEqual(case_insensitive_3byte_equal(b'ABC', b'abc'), 1)
        self.assertEqual(case_insensitive_3byte_equal(b'AbC', b'aBc'), 1)
        self.assertEqual(case_insensitive_3byte_equal(b'ABC', b'ABD'), 0)
        self.assertEqual(case_insensitive_3byte_equal(b'ABX', b'aby'), 0)
        self.assertEqual(case_insensitive_3byte_equal(b'A!C', b'a!c'), 1)
        self.assertEqual(case_insensitive_3byte_equal(b'@BC', b'`bc'), 0)

    def test_window_bytes_and_padding(self):
        data = load()
        text = section_bytes(data, '.text')
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)
        self.assertEqual(bytes(data[off + len(BODY):off + len(BODY) + 1]), b'\xcc')
        self.assertEqual(bytes(data[off - 14:off]), b'\xcc' * 14)

    def test_fde_records(self):
        data = load()
        eh = section_bytes(data, '.eh_frame')
        base = eh['offset']
        self.assertEqual(bytes(data[base:base + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[base + 0x14a00:base + 0x14a00 + len(FDE)]), FDE)
        self.assertEqual(bytes(data[base + 0x14a14:base + 0x14a14 + len(NEXT)]), NEXT)
        for offset, raw, _, _ in CALLER_FDES:
            self.assertEqual(bytes(data[base + offset:base + offset + len(raw)]), raw)

    def test_corruption_controls(self):
        # Each corruption must fail analyze: body byte, padding, FDE byte,
        # caller FDE byte, and a flipped fold constant.
        text = section_bytes(load(), '.text')
        body_off = text['offset'] + START - text['address']
        cases = []
        mutated = load()
        mutated[body_off] ^= 0xff
        cases.append(mutated)
        mutated = load()
        mutated[body_off + len(BODY)] = 0x90
        cases.append(mutated)
        eh = section_bytes(load(), '.eh_frame')
        mutated = load()
        mutated[eh['offset'] + 0x14a00 + 5] ^= 0xff
        cases.append(mutated)
        mutated = load()
        mutated[eh['offset'] + 0x14b34 + 10] ^= 0xff
        cases.append(mutated)
        mutated = load()
        mutated[body_off + 0x12] = 0x1b  # fold bound 0x1a -> 0x1b
        cases.append(mutated)
        for mutated in cases:
            with self.assertRaises(ValueError):
                analyze(bytes(mutated))

    def test_incoming_callers_and_slots(self):
        result = analyze(TARGET.read_bytes())
        self.assertEqual([hex(c) for c in result['direct_callers']],
                         ['0x151b4f9', '0x151b527'])
        self.assertEqual(result['relocation_slots'], [])

    def test_check_passes(self):
        result = analyze(TARGET.read_bytes())
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['start_va'], hex(START))
        self.assertEqual(retained['function']['end_va_exclusive'], hex(END))
        self.assertEqual(retained['function']['bytes'], END - START)
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(c) for c in result['direct_callers']])


if __name__ == '__main__':
    unittest.main()
