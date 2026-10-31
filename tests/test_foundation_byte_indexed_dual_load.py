#!/usr/bin/env python3
"""Unit tests for the node #94 byte-indexed dual-load checker.

Every test restates retained target bytes or the decoded rule; none executes
the captured binary. Corruption controls mutate one locked element at a time
and require the checker to fail.
"""
import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from elf_index import sections  # noqa: E402
from foundation_byte_indexed_dual_load import (  # noqa: E402
    BODY, CIE, END, FDE, FDE_OFFSET, NAMING_SLOT, NEXT_FDE_OFFSET,
    PAD, PAD_END, SHA256, START, TABLE_A, TABLE_A_FIRST12, TABLE_B,
    TABLE_B_RELOC_COUNT, analyze, dual_load, inspect)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-byte-indexed-dual-load-94/evidence.json'


def mutated(replace):
    data = bytearray(BINARY.read_bytes())
    secs = sections(bytes(data))
    for va, old, new in replace:
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + len(old) <= s['address'] + s['size']]
        assert len(matches) == 1, hex(va)
        s = matches[0]
        off = s['offset'] + va - s['address']
        assert data[off:off + len(old)] == old, (hex(va), data[off:off + len(old)].hex())
        data[off:off + len(old)] = new
    return bytes(data)


class DualLoadTests(unittest.TestCase):
    def test_check_passes(self):
        result = inspect(str(BINARY))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['naming_slot'], NAMING_SLOT)
        self.assertEqual(result['table_b_relocs'], TABLE_B_RELOC_COUNT)

    def test_evidence_matches(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['target_sha256'], SHA256)
        self.assertEqual(retained['function']['start_va'], hex(START))
        self.assertEqual(retained['function']['end_va_exclusive'], hex(END))
        self.assertEqual(retained['function']['bytes'], END - START)
        self.assertEqual(retained['function']['sha256'],
                         hashlib.sha256(BODY).hexdigest())
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'], [])
        self.assertEqual(retained['data_edge']['relative_slots_naming_window'],
                         [hex(NAMING_SLOT)])
        self.assertEqual(retained['data_edge']['table_b_relative_reloc_count'],
                         TABLE_B_RELOC_COUNT)

    def test_rule_edges(self):
        # Synthetic table B: the real table-B contents are load-time values
        # and are not claimed; the formula itself is restated exactly.
        a = list(TABLE_A_FIRST12)
        b = [100 + i for i in range(12)]
        self.assertEqual(dual_load(0, a, b), (8, 100))
        self.assertEqual(dual_load(1, a, b), (9, 101))
        self.assertEqual(dual_load(5, a, b), (9, 105))
        self.assertEqual(dual_load(7, a, b), (10, 107))
        self.assertEqual(dual_load(11, a, b), (6, 111))

    def test_body_shape(self):
        self.assertEqual(len(BODY), 29)
        self.assertEqual(BODY[0:3], bytes.fromhex('0fb607'))
        self.assertEqual(BODY[3:6], bytes.fromhex('c1e003'))
        self.assertEqual(BODY[6:13], bytes.fromhex('488d0deb8d97fb'))
        self.assertEqual(BODY[13:17], bytes.fromhex('488b1408'))
        self.assertEqual(BODY[17:24], bytes.fromhex('488d0d78169000'))
        self.assertEqual(BODY[24:28], bytes.fromhex('488b0408'))
        self.assertEqual(BODY[28], 0xc3)
        self.assertEqual(PAD, b'\xcc' * 3)
        self.assertEqual(PAD_END - END, 3)

    def test_fde_records(self):
        self.assertEqual(len(FDE), 16)
        self.assertEqual(FDE_OFFSET, 0x274aec)
        self.assertEqual(NEXT_FDE_OFFSET, 0x274b00)
        self.assertEqual(len(CIE), 24)
        self.assertEqual(TABLE_A, 0x7c13f8)
        self.assertEqual(TABLE_B, 0x5749c90)
        self.assertEqual(NAMING_SLOT, 0x57494c0)

    def test_corrupt_body_fails(self):
        bad = mutated([(START, bytes.fromhex('0fb607'), bytes.fromhex('0fb606'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_scale_fails(self):
        bad = mutated([(START + 3, bytes.fromhex('c1e003'), bytes.fromhex('c1e002'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_table_a_lea_fails(self):
        bad = mutated([(START + 6, bytes.fromhex('488d0deb8d97fb'),
                        bytes.fromhex('488d0deb8d97fa'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_padding_fails(self):
        bad = mutated([(END, b'\xcc', b'\x90')])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_table_a_head_fails(self):
        bad = mutated([(TABLE_A, struct.pack('<q', 8), struct.pack('<q', 7))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_table_b_head_fails(self):
        bad = mutated([(TABLE_B, b'\x00' * 8, b'\x01' + b'\x00' * 7)])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_fde_fails(self):
        # Mutate the FDE range field via the .eh_frame record itself.
        secs = sections(BINARY.read_bytes())
        eh = [s for s in secs if s['name'] == '.eh_frame'][0]
        fde_va = eh['address'] + FDE_OFFSET
        bad = mutated([(fde_va + 12, struct.pack('<I', 0x1d),
                        struct.pack('<I', 0x1c))])
        with self.assertRaises(ValueError):
            analyze(bad)


if __name__ == '__main__':
    unittest.main()
