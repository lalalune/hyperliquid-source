#!/usr/bin/env python3
"""Tests for the X5 closure environment pair source packet."""

import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / 'tools' / 'packet_env_pair_x5_static.py'
spec = importlib.util.spec_from_file_location('packet_env_pair_x5_static',
                                              TOOL)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)

MATERIALISED = (
    subject.TARGET.exists()
    and subject.TARGET.stat().st_size == subject.EXPECTED_SIZE
    and subject.identity(subject.TARGET.read_bytes())['sha256']
    == subject.EXPECTED_SHA256)


@unittest.skipUnless(MATERIALISED, 'node 115 artifact not materialised')
class PacketEnvPairX5StaticTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.payload = subject.load_records()

    def test_records_match_artifact(self):
        records = subject.build_records(self.data)
        self.assertEqual(subject.canonical(records),
                         subject.canonical(self.payload))

    def test_owner_spot_pins(self):
        owners = self.payload['owners']
        self.assertEqual(set(owners), {
            'schedule_caller_x5', 'adapter2_x5', 'adapter1_x5'})
        spot = {
            'schedule_caller_x5': (
                '0x5cf5100', '0x5cf55d7', 1239,
                '3ede3e0de6239df2546301485ff8664996a025ed907a'
                '977b2d99c6cdc054fcd8'),
            'adapter2_x5': (
                '0x5cdce30', '0x5cdd008', 472,
                '589a3b16f5013ff43e75ab39cfb136540820fcd1cc3'
                'a3ff7af6dac07763b5f12'),
            'adapter1_x5': (
                '0x5cdd010', '0x5cdd032', 34,
                '08279dcddc059d212fc800281ca155be9aa0a56c7c7'
                'a8618a47925b2d227833d'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)
        self.assertFalse(self.payload['captured_code_executed'])

    def test_slots(self):
        slots = self.payload['slots']
        self.assertEqual(slots['caller_table_slot']['slot'], '0x64e7718')
        self.assertEqual(slots['caller_table_slot']['target'], '0x5cf5100')
        self.assertEqual(slots['x5_adapter1_slot']['target'], '0x5cdd010')
        self.assertEqual(slots['x5_adapter2_slot']['target'], '0x5cdce30')

    def test_reference_audit(self):
        audit = self.payload['reference_audit']
        spawn = audit['spawn_x5']
        self.assertEqual(spawn['direct_branches'],
                         [{'kind': 'call', 'site': '0x5cf5347'}])
        self.assertEqual(spawn['reloc_addend_slots'], [])
        self.assertEqual(spawn['stored_copies_writable'], [])
        caller = audit['schedule_caller_x5']
        self.assertEqual(caller['direct_branches'], [])
        self.assertEqual(caller['reloc_addend_slots'], ['0x64e7718'])
        self.assertEqual(caller['stored_copies_writable'], [])

    def test_pair_provenance(self):
        answer = self.payload['answer']
        prov = {p['closure_offset']: p
                for p in answer['pair_provenance']}
        self.assertEqual(set(prov), {'0x28', '0x30', '0x38', '0x40'})
        self.assertEqual(prov['0x28']['arg_struct_offset'], '0x00')
        self.assertEqual(prov['0x28']['store_site'], '0x5cf530b')
        self.assertEqual(prov['0x30']['arg_struct_offset'], '0x08')
        self.assertEqual(prov['0x30']['store_site'], '0x5cf5310')
        self.assertEqual(prov['0x38']['arg_struct_offset'], '0x10')
        self.assertEqual(prov['0x38']['store_site'], '0x5cf531f')
        self.assertEqual(prov['0x40']['arg_struct_offset'], '0x18')
        self.assertEqual(prov['0x40']['store_site'], '0x5cf531a')
        self.assertIn('neither pair word is a static address',
                      answer['static_vtable'])

    def test_mutation_of_call_site_is_rejected(self):
        data = bytearray(self.data)
        off, _ = subject.read(0x5cf5347, bytes(data), 5)
        data[off + 1] ^= 0x01
        with self.assertRaises(ValueError):
            subject.check_pins(bytes(data))

    def test_mutation_of_pair_clone_is_rejected(self):
        # lock xadd [rbp],r9 -- the strong-count clone of the pair word.
        data = bytearray(self.data)
        off, _ = subject.read(0x5cf52e9, bytes(data), 6)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            subject.check_pins(bytes(data))

    def test_mutation_of_pair_store_disp_is_rejected(self):
        # mov [rsp+0x28],rbp -- the +0x08 argument store displacement.
        data = bytearray(self.data)
        off, _ = subject.read(0x5cf5310, bytes(data), 5)
        data[off + 4] ^= 0x01
        with self.assertRaises(ValueError):
            subject.check_pins(bytes(data))

    def test_mutation_of_adapter2_table_disp_is_rejected(self):
        # mov rdi,[rcx+rax+0x1f8] -- the bool-indexed table load.
        data = bytearray(self.data)
        off, _ = subject.read(0x5cdcef2, bytes(data), 8)
        data[off + 5] ^= 0x01
        with self.assertRaises(ValueError):
            subject.check_pins(bytes(data))

    def test_mutation_of_owner_body_is_rejected(self):
        data = bytearray(self.data)
        off, _ = subject.read(0x5cdd010, bytes(data), 16)
        data[off] ^= 0x01
        mutated = subject.owners(bytes(data))
        self.assertNotEqual(mutated['adapter1_x5']['sha256'],
                            self.payload['owners']['adapter1_x5']
                            ['sha256'])

    def test_mutation_of_caller_slot_is_rejected(self):
        data = bytearray(self.data)
        blob = bytes(data)
        sec = subject.sections(blob)['.rela.dyn']
        target = None
        for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
            r_offset = struct.unpack_from('<Q', blob, p)[0]
            if r_offset == 0x64e7718:
                target = p + 16  # r_addend field
                break
        self.assertIsNotNone(target)
        data[target] ^= 0x01
        mutated = subject.slot_targets(bytes(data))
        self.assertNotEqual(mutated['caller_table_slot']['target'],
                            '0x5cf5100')


if __name__ == '__main__':
    unittest.main()
