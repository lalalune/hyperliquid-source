from __future__ import annotations

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import spawn_payload_fields_static as subject
from artifacts import ROOT
from elf_index import sections

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
class SpawnPayloadFieldsStaticTest(unittest.TestCase):

    def setUp(self):
        self.data = TARGET.read_bytes()
        self.payload = subject.analyze(self.data)

    def test_regeneration_matches_packet(self):
        packet = Path(ROOT) / (
            'research/work-items/'
            'RE-005-node115-spawn-payload-fields/records.json')
        self.assertTrue(packet.is_file())
        self.assertEqual(packet.read_text(), canonical(self.payload))

    def test_owners_are_pinned(self):
        owners = self.payload['owners']
        self.assertEqual(len(owners), 6)
        spot = {
            'spawn_e': ('0x2ad6560', '0x2ad713e', 3038,
                        'c8863fdfc321585b0cd46a5bdb0bcd1bd'
                        '4c1a820ba53f9e56b6082037df03a79'),
            'slot1760_callee': ('0x5cf9600', '0x5cfa8b1', 4785,
                                '12813161d76cb5aa11039d12cbbf45d6f'
                                '170b2aa53da586df8e03b579e02d13b'),
            'direct540': ('0x2d4d540', '0x2d4d749', 521,
                          '63f8b162ab28d87a0386a5afd901c1c15de'
                          '19b023c0a6fd4d11ccd816e524dfb'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)
        self.assertFalse(self.payload['captured_code_executed'])

    def test_got_census(self):
        got = self.payload['got_census']
        self.assertEqual(got['0x64e7360']['callee'], '0x4784130')
        self.assertEqual(
            got['0x64e7360']['rip_relative_references'],
            ['0x2ad5ad2', '0x2ad66b2', '0x5a5e358', '0x5a62480'])
        self.assertEqual(got['0x64e1760']['callee'], '0x5cf9600')
        self.assertEqual(
            got['0x64e1760']['rip_relative_references'],
            ['0x15d7026', '0x15d70c2', '0x2ae16f2'])

    def test_table_census(self):
        census = self.payload['handler_table_census']
        verified = census['verified_references']
        self.assertEqual(len(verified), 12)
        targets = {entry['target'] for entry in verified}
        self.assertEqual(targets, {'0x64478a0', '0x64478b8',
                                   '0x64478d8', '0x64478f8',
                                   '0x6447910'})
        # The spawn pointers themselves are named by nothing.
        self.assertNotIn('0x64478d0', targets)
        self.assertNotIn('0x64478f0', targets)
        self.assertEqual(census['base_qword_occurrences'], 0)
        self.assertEqual(
            census['relocation_addends_into_range'], [])
        self.assertEqual(census['slots']['0x64478d0']
                         ['relative_addend'], '0x2ad6560')
        self.assertEqual(census['slots']['0x64478f0']
                         ['relative_addend'], '0x2ad5980')
        self.assertEqual(census['slots']['0x64478a0']
                         ['relative_addend'], '0x445db6')
        # The strings the statics point at, read through the
        # section table (.rodata is identity-mapped; a
        # VA - 0x1000 read names the strings 0x1000 lower).
        self.assertEqual(census['static_strings'], {
            '0x445db6': 'node/src/connections.rs',
            '0x449029': 'node/src/gossip_config.rs'})
        refuted = [c for c in census['raw_candidates']
                   if c['verdict'] == 'refuted']
        self.assertEqual(
            len(refuted) + len(verified),
            len(census['raw_candidates']))

    def test_call_census(self):
        census = self.payload['call_census']
        direct = census['direct_call_sites']['direct540']
        self.assertEqual(
            [entry['site'] for entry in direct],
            ['0x2acdedc', '0x2ad1ef6', '0x2ad60e9', '0x2ad6cc9'])
        self.assertEqual(census['direct_call_sites']
                         ['slot7360_callee'], [])
        self.assertEqual(census['direct_call_sites']
                         ['slot1760_callee'], [])
        for name in census['tail_call_sites'].values():
            self.assertEqual(name, [])

    def test_classified_census(self):
        census = self.payload['classified_census']
        slot = census['slot7360_callee']
        self.assertEqual(len(slot['stores']['r14']), 25)
        self.assertNotIn('0x8', slot['stores']['r14'])
        self.assertEqual(max(int(off, 16)
                             for off in slot['stores']['r14']),
                         0x1F8)
        direct = census['direct540']
        self.assertNotIn('rbx', direct['stores'])
        self.assertEqual(direct['loads']['rbx'],
                         {'0x0': 4, '0x8': 4})
        phase = census['slot1760_callee']
        total_sites = sum(
            len(v) for reg in phase['store_sites'].values()
            for v in reg.values())
        self.assertEqual(total_sites, 11)
        self.assertEqual(phase['r14_segment_loads']['0x68'], 2)
        self.assertEqual(phase['r14_segment_leas'], {'0xd0': 2})

    def test_findings_records(self):
        payload = self.payload['spawn_payload']
        self.assertIn('written by nothing', payload['unattributed'])
        self.assertIn('0x4784130', payload['slot7360_callee']
                      ['identity'])
        self.assertIn('none', payload['direct540']
                      ['record_writes'])
        table = self.payload['handler_table']
        self.assertIn('no walker', table['walker_verdict'])
        self.assertIn('node/src/connections.rs',
                      table['structure'])
        self.assertIn('node/src/gossip_config.rs',
                      table['structure'])
        phase = self.payload['phase_fill']
        self.assertIn('0x5cf9600', phase['identity'])
        self.assertIn('0x50', phase['extent'])

    def test_byte_mutations_break_the_claims(self):
        cases = [
            (0x2AD6CC9, 1),   # spawn_e's direct call to 0x2d4d540
            (0x2AD66B2, 2),   # spawn_e's FF 15 call via 0x64e7360
            (0x2AD59CB, 3),   # spawn_d's lea of the string static
            (0x5CFA1AA, 2),   # the phase fill's [rbx+0x28] store
            (0x2D4D5E7, 3),   # direct540's lea r15 = r14 + 0x48
        ]
        offset_base = 0x1000
        for va, skip in cases:
            mutated = bytearray(self.data)
            mutated[va - offset_base + skip] ^= 1
            with self.assertRaises(ValueError, msg=hex(va)):
                subject.analyze(bytes(mutated))

    def test_table_relocation_mutation_breaks_the_claims(self):
        mutated = bytearray(self.data)
        hit = None
        for section in sections(self.data):
            if section['name'] != '.rela.dyn':
                continue
            for i in range(section['offset'],
                           section['offset'] + section['size'], 24):
                off, _, _ = struct.unpack_from('<QQq', self.data, i)
                if off == 0x64478D0:
                    hit = i + 16
        self.assertIsNotNone(hit)
        mutated[hit] ^= 1
        with self.assertRaises(ValueError):
            subject.analyze(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
