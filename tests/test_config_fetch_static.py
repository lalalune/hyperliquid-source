from __future__ import annotations

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import config_fetch_static as subject
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
class ConfigFetchStaticTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.payload = subject.analyze(cls.data)

    def test_regeneration_matches_packet(self):
        packet = Path(ROOT) / (
            'research/work-items/'
            'RE-005-node115-config-fetch/records.json')
        self.assertTrue(packet.is_file())
        self.assertEqual(packet.read_text(), canonical(self.payload))

    def test_owners_are_pinned(self):
        owners = self.payload['owners']
        self.assertEqual(len(owners), 10)
        spot = {
            'config_fetch': ('0x1506840', '0x15069f2', 434,
                             '34189b04fb9454d33dbe002156516ed83a2d63'
                             'ae8e98c63b88a6d87119287c71'),
            'predicate': ('0x14c2a40', '0x14c2b4c', 268,
                          '3859bdfff5581cd4525e6c586973fbf0e01d84'
                          '7b4f676b5afcefd76137bb1d84'),
            'lookup_a': ('0x163a4b0', '0x163a66c', 444,
                         '579d70a866d9befafc51745673ad60ec4bd4d0c2'
                         '61e33deea54d8fea06690b88'),
            'lookup_d': ('0x564cce0', '0x564cf36', 598,
                         'e69561afd60a4ae323867f1eb25f2a6997c85c48'
                         '8524e15bf0ca9f9fed100e92'),
            'lvl4_a': ('0x2ae41e0', '0x2ae6d66', 11142,
                       '90ae09003ca680bd4b5f32fec22ee1f7146cc1f'
                       '67b758f8e2f2ac880545b730b'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)
        self.assertFalse(self.payload['captured_code_executed'])

    def test_slot_census(self):
        slots = self.payload['slot_census']
        self.assertEqual(slots['config_slot']['callee'],
                         '0x1506840')
        self.assertEqual(slots['config_slot']['slot'], '0x64e0a80')
        self.assertEqual(slots['config_global_ptr_slot']['callee'],
                         '0x64efd00')
        self.assertEqual(slots['lookup_a_slot']['callee'],
                         '0x163a4b0')
        self.assertEqual(slots['lookup_b_slot']['callee'],
                         '0x564d700')
        self.assertEqual(slots['lookup_c_slot']['callee'],
                         '0x165de90')
        self.assertEqual(slots['lookup_d_slot']['callee'],
                         '0x564cce0')
        self.assertEqual(slots['copy_slot']['symbol'], 'memcpy')
        self.assertEqual(slots['copy_slot']['relocation'],
                         'R_X86_64_GLOB_DAT')

    def test_config_slot_census(self):
        census = self.payload['config_slot_census']
        self.assertEqual(census['callee'], '0x1506840')
        self.assertEqual(census['direct_or_tail_callers'], [])
        self.assertEqual(
            census['rip_relative_references'],
            {'0x2ae4281': '0x2ae41e0..0x2ae6d66',
             '0x2aeb2e0': '0x2aeaef0..0x2af0654',
             '0x2cb68f0': '0x2cb6500..0x2cbbbdf',
             '0x2cde525': '0x2cde430..0x2ce0dd1'})

    def test_body_censuses(self):
        censuses = self.payload['body_censuses']
        fetch = censuses['config_fetch_rdi']
        self.assertEqual(fetch['stores'], {})
        self.assertEqual(fetch['leas'], {})
        self.assertEqual(fetch['other_dst'], {})
        self.assertEqual(
            sorted(fetch['loads']),
            ['0x0', '0x18', '0x20', '0x30', '0x38', '0x48',
             '0x4c', '0x8'])
        pred = censuses['predicate_rbx']
        self.assertEqual(pred['stores'], {})
        self.assertEqual(pred['loads']['0x0'],
                         ['0x14c2a97', '0x14c2ae4'])
        lookup_a = censuses['lookup_a_rdi']
        self.assertEqual(lookup_a['loads'], {})
        self.assertEqual(len(lookup_a['stores']), 44)
        # The [entry+0x40, entry+0x50) window is never stored.
        for off in ('0x40', '0x48', '0x4c', '0x4d'):
            self.assertNotIn(off, lookup_a['stores'])
        lookup_d = censuses['lookup_d_rbx']
        self.assertEqual(lookup_d['loads'], {})
        self.assertEqual(
            sorted(lookup_d['stores'], key=lambda h: int(h, 16)),
            ['0x0', '0x10', '0x20', '0x30', '0x40', '0x50',
             '0x60', '0x70', '0x78', '0x80', '0x88', '0x90'])

    def test_call_maps(self):
        maps = self.payload['call_maps']
        self.assertEqual(
            maps['builder_c']['rip_targets']['0x2b7b69b'],
            {'kind': 'call', 'target': '0x64e1d08'})
        self.assertEqual(
            maps['builder_c']['direct_calls'],
            {'0x2b7b748': '0x2ab8cc0', '0x2b7b789': '0x2ab8cc0',
             '0x2b7b791': '0x63f0a50'})
        self.assertNotIn(
            '0x64e0a80',
            [entry['target'] for entry in
             maps['builder_c']['rip_targets'].values()])
        self.assertEqual(maps['lvl4_a']['config_slot_sites'],
                         ['0x2ae4281'])
        self.assertEqual(maps['lvl3_c']['config_slot_sites'],
                         ['0x2cde525'])
        self.assertEqual(
            maps['lookup_d']['rip_targets']['0x564ce57'],
            {'kind': 'call', 'target': '0x64ebcb0'})

    def test_strings_and_globals(self):
        records = self.payload['strings_and_globals']
        self.assertEqual(records['key_string']['value'], 'hl-node')
        self.assertEqual(records['file_string']['value'],
                         'base/src/log/state.rs')
        self.assertEqual(records['chain_key']['value'], 'chain')
        self.assertEqual(records['key_key']['value'], 'key')
        self.assertEqual(records['message_string']['prefix'],
                         'enable_log not applied')
        globals_ = records['globals']
        self.assertEqual(globals_['state_byte']['file_value'],
                         '0x0')
        self.assertEqual(globals_['state_dword']['file_value'],
                         '0x3')
        self.assertEqual(
            globals_['predicate_struct']['first_qwords'],
            ['0x0', '0x0', '0x9', '0x0'])

    def test_findings_records(self):
        fetch = self.payload['config_fetch']
        self.assertIn('nothing', fetch['return'])
        self.assertIn('0x2ae4281', fetch['slot'])
        self.assertIn('base/src/log/state.rs', fetch['log_arm'])
        attribution = self.payload['record_attribution']
        self.assertIn('Mainnet', attribution['chain_tag'])
        self.assertIn('0x564cec0', attribution['lookup_d_arm'])
        self.assertIn('No store in the census covers',
                      attribution['lookup_a'])
        self.assertIn('0x2cb6500',
                      self.payload['boundaries']['next_questions'])
        self.assertIn('section table', self.payload['limits'])

    def test_byte_mutations_break_the_claims(self):
        cases = [
            (0x2AE4281, 2),   # lvl4_a's config-slot FF 15 call
            (0x2CDE525, 2),   # lvl3_c's config-slot FF 15 call
            (0x1506859, 0),   # the callee's tag compare
            (0x564CD5C, 0),   # lookup_d's "Mainnet" compare
        ]
        offset_base = 0x1000
        for va, skip in cases:
            mutated = bytearray(self.data)
            mutated[va - offset_base + skip] ^= 1
            with self.assertRaises(ValueError, msg=hex(va)):
                subject.analyze(bytes(mutated))

    def test_config_relocation_mutation_breaks_the_claims(self):
        mutated = bytearray(self.data)
        hit = None
        for section in sections(self.data):
            if section['name'] != '.rela.dyn':
                continue
            for i in range(section['offset'],
                           section['offset'] + section['size'], 24):
                off, _, _ = struct.unpack_from('<QQq', self.data, i)
                if off == 0x64E0A80:
                    hit = i + 16
        self.assertIsNotNone(hit)
        mutated[hit] ^= 1
        with self.assertRaises(ValueError):
            subject.analyze(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
