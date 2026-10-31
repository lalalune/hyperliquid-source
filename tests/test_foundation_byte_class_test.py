#!/usr/bin/env python3
"""Unit tests for the node #94 byte-class test checker.

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
from foundation_byte_class_test import (  # noqa: E402
    BODY, CALLER, CALLER_BYTES, CALLER_FDE_HEAD, CALLER_FDE_OFFSET,
    CALLER_SETUP_MOV, CALLER_SETUP_MOVSBL, CIE, END, FDE, FDE_OFFSET, MASK,
    MASK_BITS, NEXT_FDE_OFFSET, PAD, PAD_END, SHA256, START, analyze,
    byte_class, inspect)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-byte-class-test-94/evidence.json'


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


class ByteClassTests(unittest.TestCase):
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
        self.assertEqual(retained['behavior']['bt_mask_bits'], list(MASK_BITS))
        self.assertEqual(retained['behavior']['accepted_set'],
                         ["0x0a", "0x0d", "0x23", "0x3a", "0x5c"])

    def test_rule_edges(self):
        # The five accepted bytes, and the boundaries around them.
        for b in (0x0a, 0x0d, 0x23, 0x3a, 0x5c):
            self.assertEqual(byte_class(b), 1, hex(b))
        for b in (0x00, 0x09, 0x0b, 0x0c, 0x0e, 0x22, 0x24, 0x39, 0x3b,
                  0x5b, 0x5d, 0x7f, 0x80, 0xff):
            self.assertEqual(byte_class(b), 0, hex(b))

    def test_signed_reading(self):
        # Bytes 0x80..0xff read as negative: they miss the > 0x22 path and
        # are not 0x0a/0x0d, so they return 0.
        for b in (0x80, 0xa0, 0xc0, 0xfe, 0xff):
            self.assertEqual(byte_class(b), 0, hex(b))
        # Bytes 0x5d..0x7f read as signed > 0x5c, so they return 0 even
        # though 0x5c itself (bit 57) returns 1.
        for b in (0x5d, 0x60, 0x7f):
            self.assertEqual(byte_class(b), 0, hex(b))

    def test_mod64_caveat(self):
        # With a non-extended edi, the bit-test index is (edi - 0x23) mod 64.
        # edi = 0x23 + 64 tests bit 0 again -> 1; edi = 0x23 + 1 tests bit 1 -> 0.
        self.assertEqual(byte_class(0x23, edi=0x23 + 64), 1)
        self.assertEqual(byte_class(0x23, edi=0x23 + 1), 0)
        # The confirmed caller sign-extends, so byte 0x23 gives index 0 -> 1.
        self.assertEqual(byte_class(0x23, edi=0x23), 1)

    def test_body_shape(self):
        self.assertEqual(len(BODY), 69)
        self.assertEqual(BODY[0:4], bytes.fromhex('f30f1efa'))
        self.assertEqual(BODY[4:6], bytes.fromhex('31c0'))
        self.assertEqual(BODY[6:10], bytes.fromhex('4080ff5c'))
        self.assertEqual(BODY[10:12], bytes.fromhex('7f19'))
        self.assertEqual(BODY[12:16], bytes.fromhex('4080ff22'))
        self.assertEqual(BODY[16:18], bytes.fromhex('7f1e'))
        self.assertEqual(BODY[18:22], bytes.fromhex('4080ff0a'))
        self.assertEqual(BODY[22:24], bytes.fromhex('7408'))
        self.assertEqual(BODY[24:28], bytes.fromhex('4080ff0d'))
        self.assertEqual(BODY[28:31], bytes.fromhex('0f94c0'))
        self.assertEqual(BODY[31:32], bytes.fromhex('c3'))
        self.assertEqual(BODY[32:37], bytes.fromhex('b801000000'))
        self.assertEqual(BODY[37:38], bytes.fromhex('c3'))
        self.assertEqual(BODY[38:48], bytes.fromhex('662e0f1f840000000000'))
        self.assertEqual(BODY[48:58], bytes.fromhex('48b80100800000000002'))
        self.assertEqual(BODY[58:61], bytes.fromhex('83ef23'))
        self.assertEqual(BODY[61:65], bytes.fromhex('480fa3f8'))
        self.assertEqual(BODY[65:68], bytes.fromhex('0f92c0'))
        self.assertEqual(BODY[68:69], bytes.fromhex('c3'))
        self.assertEqual(PAD, b'\xcc' * 11)
        self.assertEqual(PAD_END - END, 11)
        self.assertEqual([i for i in range(64) if MASK >> i & 1],
                         [0, 23, 57])

    def test_fde_records(self):
        self.assertEqual(len(FDE), 20)
        self.assertEqual(FDE_OFFSET, 0x2badd4)
        self.assertEqual(NEXT_FDE_OFFSET, 0x2bade8)
        self.assertEqual(len(CIE), 24)
        self.assertEqual(len(CALLER_FDE_HEAD), 16)
        self.assertEqual(CALLER_FDE_OFFSET, 0x65d378)
        self.assertEqual(CALLER, 0x54309be)
        self.assertEqual(CALLER_BYTES, bytes.fromhex('e89dfeffff'))
        self.assertEqual(CALLER_SETUP_MOVSBL, bytes.fromhex('440fbe7d00'))
        self.assertEqual(CALLER_SETUP_MOV, bytes.fromhex('4489ff'))

    def test_corrupt_body_fails(self):
        bad = mutated([(START, bytes.fromhex('f30f1efa'), bytes.fromhex('f30f1efb'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_mask_fails(self):
        # Flipping one mask byte changes the accepted set (bit 23 -> bit 22).
        bad = mutated([(START + 48, bytes.fromhex('48b80100800000000002'),
                        bytes.fromhex('48b80100400000000002'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_compare_fails(self):
        bad = mutated([(START + 6, bytes.fromhex('4080ff5c'),
                        bytes.fromhex('4080ff5b'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_padding_fails(self):
        bad = mutated([(END, b'\xcc', b'\x90')])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_caller_call_fails(self):
        bad = mutated([(CALLER, bytes.fromhex('e89dfeffff'),
                        bytes.fromhex('e89dfefffe'))])
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_corrupt_caller_setup_fails(self):
        bad = mutated([(0x54309b3, bytes.fromhex('440fbe7d00'),
                        bytes.fromhex('440fbe7d01'))])
        with self.assertRaises(ValueError):
            analyze(bad)


if __name__ == '__main__':
    unittest.main()
