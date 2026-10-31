#!/usr/bin/env python3
"""Unit tests for the node #94 tag-dispatched-store checker.

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
from foundation_tag_dispatched_store import (  # noqa: E402
    BODY, CIE, END, FDE, GLOBAL, PAD, PAD_END, SHA256, START,
    analyze, inspect, store)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-tag-dispatched-store-94/evidence.json'


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


class TagDispatchedStoreTests(unittest.TestCase):
    def test_check_passes(self):
        result = inspect(str(BINARY))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['global'], GLOBAL)

    def test_evidence_matches(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['target_sha256'], SHA256)
        self.assertEqual(retained['function']['start_va'], hex(START))
        self.assertEqual(retained['function']['end_va_exclusive'], hex(END))
        self.assertEqual(retained['function']['bytes'], END - START)
        self.assertEqual(retained['function']['sha256'],
                         hashlib.sha256(BODY).hexdigest())
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'], [])
        self.assertEqual(retained['data_edge']['relative_slots_naming_window'], [])
        self.assertEqual(retained['data_edge']['global_pointer_va'], hex(GLOBAL))

    def test_rule_edges(self):
        self.assertEqual(store(0), ('global', GLOBAL))
        self.assertEqual(store(1), ('rsi',))
        self.assertEqual(store(2), ('copy16',))
        self.assertEqual(store(3), ('none',))
        self.assertEqual(store(4), ('none',))
        self.assertEqual(store(0xffffffff), ('none',))

    def test_body_shape(self):
        self.assertEqual(len(BODY), 61)
        self.assertEqual(BODY[0:4], bytes.fromhex('f30f1efa'))
        self.assertEqual(BODY[4:6], bytes.fromhex('85d2'))
        self.assertEqual(BODY[6:8], bytes.fromhex('7428'))
        self.assertEqual(BODY[8:11], bytes.fromhex('83fa01'))
        self.assertEqual(BODY[11:13], bytes.fromhex('750b'))
        self.assertEqual(BODY[13:16], bytes.fromhex('488937'))
        self.assertEqual(BODY[16:18], bytes.fromhex('31c0'))
        self.assertEqual(BODY[18], 0xc3)
        self.assertEqual(BODY[19:24], bytes.fromhex('0f1f440000'))
        self.assertEqual(BODY[24:27], bytes.fromhex('83fa02'))
        self.assertEqual(BODY[27:29], bytes.fromhex('75f3'))
        self.assertEqual(BODY[29:33], bytes.fromhex('f30f6f06'))
        self.assertEqual(BODY[33:36], bytes.fromhex('0f1107'))
        self.assertEqual(BODY[36:38], bytes.fromhex('ebea'))
        self.assertEqual(BODY[38:48], bytes.fromhex('662e0f1f840000000000'))
        self.assertEqual(BODY[48:55], bytes.fromhex('488d05691b7000'))
        self.assertEqual(BODY[55:58], bytes.fromhex('488907'))
        self.assertEqual(BODY[58:60], bytes.fromhex('31c0'))
        self.assertEqual(BODY[60], 0xc3)
        self.assertEqual(PAD, b'\xcc' * 3)
        self.assertEqual(PAD_END - END, 3)

    def test_fde_records(self):
        self.assertEqual(len(FDE), 20)
        self.assertEqual(struct.unpack_from('<I', FDE, 12)[0], 0x3d)
        self.assertEqual(CIE[:4], bytes.fromhex('14000000'))
        self.assertEqual(GLOBAL, 0x57592a0)

    def test_window_byte_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START, bytes([BODY[0]]), b'\x90')]))

    def test_tag_compare_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START + 10, b'\x01', b'\x02')]))

    def test_padding_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(END, b'\xcc', b'\x90')]))

    def test_lea_displacement_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START + 51, b'\x69', b'\x68')]))


if __name__ == '__main__':
    unittest.main()
