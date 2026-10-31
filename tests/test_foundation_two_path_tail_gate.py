#!/usr/bin/env python3
"""Unit tests for the node #94 two-path tail-gate checker.

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
from foundation_two_path_tail_gate import (  # noqa: E402
    BODY, CALLERS, CIE, END, FDE, PAD, PAD_END, SHA256, START,
    TAIL20, TAIL60, analyze, gate, inspect)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-two-path-tail-gate-94/evidence.json'


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


class TwoPathTailGateTests(unittest.TestCase):
    def test_check_passes(self):
        result = inspect(str(BINARY))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['callers'], [c[3] for c in CALLERS])
        self.assertEqual(result['tails'], (TAIL20, TAIL60))

    def test_evidence_matches(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['target_sha256'], SHA256)
        self.assertEqual(retained['function']['start_va'], hex(START))
        self.assertEqual(retained['function']['end_va_exclusive'], hex(END))
        self.assertEqual(retained['function']['bytes'], END - START)
        self.assertEqual(retained['function']['sha256'],
                         hashlib.sha256(BODY).hexdigest())
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(c[3]) for c in CALLERS])
        self.assertEqual(retained['data_edge']['relative_slots_naming_window'], [])
        self.assertFalse(retained['behavior']['tail_targets_decoded'])

    def test_rule_edges(self):
        self.assertEqual(gate(3, 3), ('tail60', TAIL60))
        self.assertEqual(gate(3, 0), ('ret', None))
        self.assertEqual(gate(3, 4), ('ret', None))
        self.assertEqual(gate(4, 0), ('tail20', TAIL20))
        self.assertEqual(gate(4, 3), ('tail20', TAIL20))
        self.assertEqual(gate(0, 0), ('ret', None))
        self.assertEqual(gate(5, 3), ('ret', None))
        self.assertEqual(gate(0xff, 0xff), ('ret', None))

    def test_body_shape(self):
        self.assertEqual(len(BODY), 42)
        self.assertEqual(BODY[0:4], bytes.fromhex('0fb64715'))
        self.assertEqual(BODY[4:7], bytes.fromhex('83f803'))
        self.assertEqual(BODY[7:9], bytes.fromhex('740e'))
        self.assertEqual(BODY[9:12], bytes.fromhex('83f804'))
        self.assertEqual(BODY[12:14], bytes.fromhex('751b'))
        self.assertEqual(BODY[14:18], bytes.fromhex('4883c720'))
        self.assertEqual(BODY[18:23], bytes.fromhex('e9f922feff'))
        self.assertEqual(BODY[23:30], bytes.fromhex('80bf400d000003'))
        self.assertEqual(BODY[30:32], bytes.fromhex('7509'))
        self.assertEqual(BODY[32:36], bytes.fromhex('4883c760'))
        self.assertEqual(BODY[36:41], bytes.fromhex('e97744feff'))
        self.assertEqual(BODY[41], 0xc3)
        self.assertEqual(PAD, b'\xcc' * 6)
        self.assertEqual(END - START, 42)
        self.assertEqual(PAD_END - END, 6)

    def test_tail_targets(self):
        self.assertEqual(START + 18 + 5 + struct.unpack_from('<i', BODY, 19)[0], TAIL20)
        self.assertEqual(START + 36 + 5 + struct.unpack_from('<i', BODY, 37)[0], TAIL60)

    def test_corrupt_body_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START, bytes.fromhex('0fb64715'), bytes.fromhex('0fb64716'))]))

    def test_corrupt_tag_compare_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START + 4, bytes.fromhex('83f803'), bytes.fromhex('83f804'))]))

    def test_corrupt_tail_jump_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START + 18, bytes.fromhex('e9f922feff'), bytes.fromhex('e9f822feff'))]))

    def test_corrupt_padding_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(END, b'\xcc', b'\x90')]))

    def test_corrupt_caller_fails(self):
        site = CALLERS[0][3]
        with self.assertRaises(ValueError):
            analyze(mutated([(site, bytes.fromhex('e8212af9ff'), bytes.fromhex('e8212af8ff'))]))

    def test_corrupt_setup_fails(self):
        site = CALLERS[1][3]
        with self.assertRaises(ValueError):
            analyze(mutated([(site - 3, bytes.fromhex('4c89ef'), bytes.fromhex('4c89ee'))]))


if __name__ == '__main__':
    unittest.main()
