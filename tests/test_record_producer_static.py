from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import record_producer_static as subject
from artifacts import ROOT

TARGET = ROOT_DIR / 'artifacts/node/115/hl-node'
DATA = TARGET.read_bytes() if TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == subject.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == subject.TARGET_SHA256)


def canonical(payload):
    return json.dumps(payload, indent=1, sort_keys=True) + '\n'


@unittest.skipUnless(
    MATERIALISED,
    'the node 115 ELF artifact is not materialised')
class RecordProducerStaticTest(unittest.TestCase):

    def setUp(self):
        self.data = TARGET.read_bytes()
        self.payload = subject.analyze(self.data)

    def test_regeneration_matches_packet(self):
        packet = Path(ROOT) / (
            'research/work-items/'
            'RE-005-node115-record-producer/records.json')
        self.assertTrue(packet.is_file())
        self.assertEqual(packet.read_text(), canonical(self.payload))

    def test_owners_are_pinned(self):
        owners = self.payload['owners']
        self.assertEqual(len(owners), 22)
        spot = {
            'lvl3_a': ('0x2aeaef0', '0x2af0654', 22372,
                       'd1b4e3ecb40fb4027b69240f48eacf2d'
                       'e2cf5f7e8c3ae5c0e6910a784fdcce29'),
            'spawn_e': ('0x2ad6560', '0x2ad713e', 3038,
                        'c8863fdfc321585b0cd46a5bdb0bcd1bd'
                        '4c1a820ba53f9e56b6082037df03a79'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)
        self.assertFalse(self.payload['captured_code_executed'])

    def test_call_census(self):
        census = self.payload['call_census']
        callers = subject.EXPECTED_CALLERS
        for name, expected in callers.items():
            self.assertEqual(
                census['direct_call_sites'][name], expected, name)
            self.assertEqual(census['tail_call_sites'][name], [], name)
        self.assertEqual(census['lea_references']['ctor_c'],
                         ['0x2cef8f7'])
        self.assertEqual(census['lea_references']
                         ['registrar_stub_c'], ['0x1419318'])
        self.assertEqual(census['lea_references']['spawn_d'], [])
        self.assertEqual(len(census['direct_call_sites']
                             ['registrar_a']), 14)
        self.assertEqual(len(census['direct_call_sites']
                             ['registrar_b']), 14)

    def test_access_census(self):
        access = self.payload['access_census']
        for role, entry in access.items():
            for _, count in entry['zero_patterns'].items():
                self.assertEqual(count, 0, role)
        self.assertEqual(access['lvl3_a']['exact_counts']
                         ['[rbx+0x1728]'], 2)
        self.assertEqual(access['lvl3_d1']['exact_counts']
                         ['[rbx+0x38]'], 1)
        self.assertEqual(access['lvl4_a']['exact_counts']
                         ['[rbx+0x248]'], 10)
        self.assertEqual(access['lvl3_c']['exact_counts']
                         ['[r13+0x248]'], 10)
        self.assertEqual(access['spawn_e']['exact_counts']
                         ['[rsp+0x3390]'], 2)

    def test_slot_census(self):
        slots = self.payload['slot_census']
        self.assertEqual(slots['spawn_d']['relocation']['slot'],
                         '0x64478f0')
        self.assertEqual(slots['spawn_d']
                         ['rip_relative_references_to_slot'], [])
        self.assertEqual(slots['lvl3_d1']
                         ['rip_relative_references_to_slot'],
                         ['0x2cd113e'])
        self.assertEqual(
            slots['spawn_d']['neighbour_addends'],
            {'0x64478d0': '0x2ad6560', '0x64478d8': '0x2a9e0f0',
             '0x64478f8': '0x445db6', '0x6447910': '0x449029'})
        self.assertEqual(
            len(slots['lvl3_d1']['neighbour_addends']), 9)

    def test_findings_records(self):
        producer = self.payload['record_producer']
        self.assertIn('no direct store', producer['descriptor_fields']
                      ['verdict'])
        self.assertIn('spawn_d', producer['d_e_chain_producer']
                      ['payload_origin'])
        self.assertIn('0x2cd7ac0', producer['pr2300_boundary'])
        self.assertIn('handler table', producer['d_e_chain_producer']
                      ['spawn_reachability'])
        self.assertIn('0x64e1760', self.payload['boundaries']
                      ['descriptor_and_head_first_writer'])

    def test_byte_mutations_break_the_claims(self):
        cases = [
            (0x2AEC151, 1),   # lvl3_a's call to lvl2_a
            (0x2CD0F4E, 3),   # wrap_e1's slot-address lea
            (0x2AD6F05, 1),   # spawn_e's call to pre_e1
            (0x2CD83A2, 1),   # ctor_c's call to lvl4_c
            (0x2B1DB7B, 3),   # lvl3_d1's record lea
            (0x2AE4627, 1),   # lvl4_a's call to lvl3_a
        ]
        offset_base = 0x1000
        for va, skip in cases:
            mutated = bytearray(self.data)
            mutated[va - offset_base + skip] ^= 1
            with self.assertRaises(ValueError, msg=hex(va)):
                subject.analyze(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
