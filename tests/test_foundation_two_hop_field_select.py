#!/usr/bin/env python3
"""Unit tests for the node #94 two-hop field select checker.

Every test restates retained target bytes or the decoded rule; none executes
the captured binary. Corruption controls mutate one locked element at a time
and require the checker to fail.
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from elf_index import sections  # noqa: E402
from foundation_two_hop_field_select import (  # noqa: E402
    BODY, CALLER_BYTES, CALLER_FDE_HEADS, CALLER_FDE_OFFSETS, CALLER_RANGES,
    CALLERS, CIE, END, FDE, FDE_OFFSET, NEXT_FDE_HEAD, NEXT_FDE_OFFSET,
    PAD_END, SHA256, START, analyze, inspect, two_hop)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-two-hop-field-select-94/evidence.json'


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


class TwoHopTests(unittest.TestCase):
    def test_check_passes(self):
        result = inspect(str(BINARY))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['callers'], CALLERS)

    def test_evidence_matches(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['target_sha256'], SHA256)
        self.assertEqual(retained['function']['start_va'], hex(START))
        self.assertEqual(retained['function']['end_va_exclusive'], hex(END))
        self.assertEqual(retained['function']['bytes'], END - START)
        self.assertEqual(retained['function']['sha256'],
                         hashlib.sha256(BODY).hexdigest())
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(c) for c in CALLERS])
        self.assertEqual(retained['data_edge']['relative_slots_naming_window'], [])
        self.assertEqual(retained['function']['padding_bytes'], 0)
        self.assertEqual(retained['function']['padding_stride_end'], hex(END))
        self.assertEqual(retained['incoming_pattern_scan']['validated_caller_fdes'],
                         ['0x5380f50..0x53814d0', '0x53825f0..0x5382c46'])

    def test_rule_edges(self):
        # Nonzero q returns [q+0x8]; null q returns [p+0x178]; zero values pass through.
        self.assertEqual(two_hop({0x178: 7}, {0x8: 42}), 42)
        self.assertEqual(two_hop({0x178: 7}, None), 7)
        self.assertEqual(two_hop({0x178: 0}, {0x8: 0}), 0)
        self.assertEqual(two_hop({0x178: 0xffff}, {0x8: 1}), 1)
        self.assertEqual(two_hop({0x178: 1}, None), 1)

    def test_body_shape(self):
        self.assertEqual(len(BODY), 40)
        self.assertEqual(BODY[0:4], bytes.fromhex('f30f1efa'))
        self.assertEqual(BODY[4:8], bytes.fromhex('488b5708'))
        self.assertEqual(BODY[8:15], bytes.fromhex('488b82e0010000'))
        self.assertEqual(BODY[15:18], bytes.fromhex('4885c0'))
        self.assertEqual(BODY[18:20], bytes.fromhex('740c'))
        self.assertEqual(BODY[20:24], bytes.fromhex('488b4008'))
        self.assertEqual(BODY[24:25], bytes.fromhex('c3'))
        self.assertEqual(BODY[25:32], bytes.fromhex('0f1f8000000000'))
        self.assertEqual(BODY[32:39], bytes.fromhex('488b8278010000'))
        self.assertEqual(BODY[39:40], bytes.fromhex('c3'))
        self.assertEqual(PAD_END, END)

    def test_fde_records(self):
        self.assertEqual(len(FDE), 16)
        self.assertEqual(FDE_OFFSET, 0x2b2a18)
        self.assertEqual(len(NEXT_FDE_HEAD), 16)
        self.assertEqual(NEXT_FDE_OFFSET, 0x65342c)
        self.assertEqual(len(CIE), 24)
        self.assertEqual(CALLER_FDE_OFFSETS, (0x654500, 0x65466c))
        self.assertEqual(CALLER_RANGES, ((0x5380f50, 0x53814d0),
                                         (0x53825f0, 0x5382c46)))
        self.assertEqual(CALLERS, (0x5380fb7, 0x538265a))
        self.assertEqual(CALLER_BYTES, (bytes.fromhex('e85407feff'),
                                        bytes.fromhex('e8b1f0fdff')))
        self.assertEqual(len(CALLER_FDE_HEADS[0]), 16)
        self.assertEqual(len(CALLER_FDE_HEADS[1]), 16)

    def test_corrupt_body_fails(self):
        bad = mutated([(START, bytes.fromhex('f30f1efa'), bytes.fromhex('f30f1efb'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_first_hop_fails(self):
        # Changing the first-hop offset 0x8 -> 0x9 breaks the rule.
        bad = mutated([(START + 4, bytes.fromhex('488b5708'),
                        bytes.fromhex('488b5709'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_second_hop_fails(self):
        # Changing the second-hop offset 0x1e0 -> 0x1e1 breaks the rule.
        bad = mutated([(START + 8, bytes.fromhex('488b82e0010000'),
                        bytes.fromhex('488b82e1010000'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_fallback_fails(self):
        # Changing the fallback offset 0x178 -> 0x179 breaks the rule.
        bad = mutated([(START + 32, bytes.fromhex('488b8278010000'),
                        bytes.fromhex('488b8279010000'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_null_branch_fails(self):
        bad = mutated([(START + 18, bytes.fromhex('740c'),
                        bytes.fromhex('750c'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_caller_call_fails(self):
        bad = mutated([(CALLERS[0], bytes.fromhex('e85407feff'),
                        bytes.fromhex('e85407fefe'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_second_caller_call_fails(self):
        bad = mutated([(CALLERS[1], bytes.fromhex('e8b1f0fdff'),
                        bytes.fromhex('e8b1f0fdfe'))])
        with self.assertRaises(ValueError):
            analyze(bad)


if __name__ == '__main__':
    unittest.main()
