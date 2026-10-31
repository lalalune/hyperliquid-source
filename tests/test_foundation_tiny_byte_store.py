#!/usr/bin/env python3
"""Unit tests for the node #94 tiny-byte-store checker.

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
from foundation_tiny_byte_store import (  # noqa: E402
    BODY, CIE, END, FDE, PAD, PAD_END, RELATIVE_SLOTS, SHA256, START,
    analyze, inspect, store)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-tiny-byte-store-94/evidence.json'


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


class TinyByteStoreTests(unittest.TestCase):
    def test_check_passes(self):
        result = inspect(str(BINARY))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['relative_slots'], RELATIVE_SLOTS)

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
                         [hex(s) for s in RELATIVE_SLOTS])

    def test_rule_edges(self):
        self.assertEqual(store(0x00), 0x5a)
        self.assertEqual(store(0x01), 0x57)
        self.assertEqual(store(0x02), 0x57)
        self.assertEqual(store(0x7f), 0x57)
        self.assertEqual(store(0xff), 0x57)

    def test_body_shape(self):
        self.assertEqual(len(BODY), 25)
        self.assertEqual(BODY[0:2], bytes.fromhex('31c0'))
        self.assertEqual(BODY[2:9], bytes.fromhex('80bff201000000'))
        self.assertEqual(BODY[9:12], bytes.fromhex('0f94c0'))
        self.assertEqual(BODY[12:15], bytes.fromhex('8d0440'))
        self.assertEqual(BODY[15:18], bytes.fromhex('83c057'))
        self.assertEqual(BODY[18:24], bytes.fromhex('8887f3010000'))
        self.assertEqual(BODY[24], 0xc3)
        self.assertEqual(PAD, b'\xcc' * 7)
        self.assertEqual(PAD_END - END, 7)

    def test_fde_records(self):
        self.assertEqual(len(FDE), 20)
        self.assertEqual(struct.unpack_from('<I', FDE, 12)[0], 0x19)
        self.assertEqual(CIE[:4], bytes.fromhex('14000000'))
        self.assertEqual(len(RELATIVE_SLOTS), 10)
        self.assertTrue(all(s & 0x30 == 0x30 for s in RELATIVE_SLOTS))

    def test_window_byte_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START, bytes([BODY[0]]), b'\x90')]))

    def test_add_immediate_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START + 17, b'\x57', b'\x56')]))

    def test_padding_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(END, b'\xcc', b'\x90')]))

    def test_pointer_table_slot_corruption_fails(self):
        # Mutate the addend of the first RELATIVE slot entry (offset field
        # is at the slot address; the addend is 16 bytes into the 24-byte
        # RELA entry). The checker reads relocations by section, so the
        # mutated file must fail the exact-slot lock.
        slot = RELATIVE_SLOTS[0]
        secs = sections(BINARY.read_bytes())
        rel = [s for s in secs if s['name'] == '.rela.dyn'][0]
        raw = BINARY.read_bytes()[rel['offset']:rel['offset'] + rel['size']]
        entry_off = None
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if address == slot:
                entry_off = off
                break
        self.assertIsNotNone(entry_off)
        # The slot's addend lives in the file at the entry's file offset + 16.
        entry_va = rel['address'] + entry_off + 16
        old = struct.pack('<q', START)
        new = struct.pack('<q', START + 1)
        with self.assertRaises(ValueError):
            analyze(mutated([(entry_va, old, new)]))


if __name__ == '__main__':
    unittest.main()
