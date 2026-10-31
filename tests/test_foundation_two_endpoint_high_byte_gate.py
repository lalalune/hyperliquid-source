#!/usr/bin/env python3
"""Unit tests for the node #94 two-endpoint high-byte gate checker.

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
from foundation_two_endpoint_high_byte_gate import (  # noqa: E402
    BODY, CALLER, CALLER_BYTES, CALLER_FDE_HEAD, CALLER_FDE_OFFSET,
    CALLER_SETUP_RCX, CALLER_SETUP_RDI, CALLER_SETUP_RDX, CALLER_SETUP_RSI,
    CIE, END, FDE, FDE_OFFSET, SHA256, START, analyze, gate, inspect,
    signed)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-two-endpoint-high-byte-gate-94/evidence.json'


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


class TwoEndpointGateTests(unittest.TestCase):
    def test_check_passes(self):
        result = inspect(str(BINARY))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['caller'], CALLER)

    def test_evidence_matches(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['target_sha256'], SHA256)
        self.assertEqual(retained['function']['start_va'], hex(START))
        self.assertEqual(retained['function']['end_va_exclusive'], hex(END))
        self.assertEqual(retained['function']['bytes'], END - START)
        self.assertEqual(retained['function']['sha256'],
                         hashlib.sha256(BODY).hexdigest())
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(CALLER)])
        self.assertEqual(retained['data_edge']['relative_slots_naming_window'], [])
        self.assertEqual(retained['function']['padding_bytes'], 0)
        self.assertEqual(retained['behavior']['rejected_set'], 'unsigned byte 0x80..0xbf (signed byte -128..-65); stated literally and not assigned to a category')

    def test_rule_edges(self):
        base, rcx = 0x1000, 0x10
        mem = {base + i: 0x41 for i in range(0x20)}
        # Clean path returns base + rdi.
        self.assertEqual(gate(0x2, 0x8, base, rcx, mem), base + 0x2)
        self.assertEqual(gate(0x0, 0x10, base, rcx, mem), base)
        # Reversed span and past-limit indices return 0.
        self.assertEqual(gate(0x8, 0x2, base, rcx, mem), 0)
        self.assertEqual(gate(0x11, 0x12, base, rcx, mem), 0)
        self.assertEqual(gate(0x2, 0x11, base, rcx, mem), 0)
        # Indices exactly at the limit skip their byte check.
        self.assertEqual(gate(0x10, 0x10, base, rcx, mem), base + 0x10)
        # Rejected bytes at either endpoint return 0.
        for bad in (0x80, 0x90, 0xbf):
            m = dict(mem)
            m[base + 0x2] = bad
            self.assertEqual(gate(0x2, 0x8, base, rcx, m), 0, hex(bad))
            m = dict(mem)
            m[base + 0x8] = bad
            self.assertEqual(gate(0x2, 0x8, base, rcx, m), 0, hex(bad))
        # All other bytes pass at either endpoint.
        for good in (0x00, 0x41, 0x7f, 0xc0, 0xff):
            m = dict(mem)
            m[base + 0x2] = good
            m[base + 0x8] = good
            self.assertEqual(gate(0x2, 0x8, base, rcx, m), base + 0x2, hex(good))

    def test_signed_reading(self):
        # The gates reject signed byte <= -65, i.e. unsigned 0x80..0xbf.
        for b in (0x80, 0xbf):
            self.assertLessEqual(signed(b), -65)
        for b in (0x00, 0x7f, 0xc0, 0xff):
            self.assertGreater(signed(b), -65)

    def test_body_corruption_fails(self):
        bad = bytearray(BODY)
        bad[19] ^= 0x01  # start byte compare immediate
        with self.assertRaises(ValueError):
            analyze(mutated([(START, BODY, bytes(bad))]))

    def test_fde_corruption_fails(self):
        bad = bytearray(FDE)
        bad[12] ^= 0x01  # FDE range field
        with self.assertRaises(ValueError):
            analyze(mutated([(0xce1518 + FDE_OFFSET, FDE, bytes(bad))]))

    def test_caller_corruption_fails(self):
        bad = bytearray(CALLER_BYTES)
        bad[1] ^= 0x01  # call rel32
        with self.assertRaises(ValueError):
            analyze(mutated([(CALLER, CALLER_BYTES, bytes(bad))]))

    def test_caller_setup_corruption_fails(self):
        bad = bytearray(CALLER_SETUP_RDI)
        bad[4] ^= 0x01  # rdi stack slot displacement
        with self.assertRaises(ValueError):
            analyze(mutated([(0x3cd2a8e, CALLER_SETUP_RDI, bytes(bad))]))


if __name__ == '__main__':
    unittest.main()
