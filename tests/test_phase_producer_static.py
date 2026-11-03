from __future__ import annotations

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import phase_producer_static as subject
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
class PhaseProducerStaticTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.payload = subject.analyze(cls.data)

    def test_regeneration_matches_packet(self):
        packet = Path(ROOT) / (
            'research/work-items/'
            'RE-005-node115-phase-producer/records.json')
        self.assertTrue(packet.is_file())
        self.assertEqual(packet.read_text(), canonical(self.payload))

    def test_owners_are_pinned(self):
        owners = self.payload['owners']
        self.assertEqual(len(owners), 10)
        spot = {
            'lvl4_c': ('0x2ae1690', '0x2ae27b2', 4386,
                       '6ca0595c13836bca0cb0173bd591a09d6da6791532'
                       'e23a5a71c63715380727d9'),
            'ctor_c': ('0x2cd8370', '0x2cd83af', 63,
                       'ed23bc89640a43b1a5f373d5cb18929d79ce5b4792'
                       '3e58ba0565f592ba2b60d6'),
            'registrar_c': ('0x5c99970', '0x5c9a045', 1749,
                            '85c321c5ef4dd64cd999ac133e97a170ffa7d08'
                            '8eab3fe7fcb64f31768181111'),
            'call4a_b': ('0x2b404b0', '0x2b40666', 438,
                         '05ef87dc8cdf209d34d246b129dfe209764fe409'
                         'efda8ee0ad73ceebb54fedac'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)
        self.assertFalse(self.payload['captured_code_executed'])

    def test_got_census(self):
        got = self.payload['got_census']
        self.assertEqual(got['registrar_slot']['callee'],
                         '0x5c99970')
        self.assertEqual(
            got['registrar_slot']['rip_relative_references'],
            ['0x2cef90f'])
        self.assertEqual(got['fill_slot']['callee'], '0x5cf9600')
        self.assertEqual(
            got['fill_slot']['rip_relative_references'],
            ['0x15d7026', '0x15d70c2', '0x2ae16f2'])
        self.assertEqual(got['copy_slot']['symbol'], 'memcpy')
        self.assertEqual(got['copy_slot']['relocation'],
                         'R_X86_64_GLOB_DAT')
        self.assertEqual(
            got['copy_slot']['lvl4_c_ff15_sites'],
            ['0x2ae1768', '0x2ae18f1', '0x2ae194c', '0x2ae19cc',
             '0x2ae1b1f'])
        self.assertEqual(got['config_slot']['callee'],
                         '0x1506840')

    def test_key_cell_census(self):
        cell = self.payload['key_cell']
        self.assertEqual(cell['file_qword'], '0x0')
        self.assertIsNone(cell['relocation'])
        self.assertEqual(cell['rip_relative_references'],
                         ['0x2cef902'])
        self.assertEqual(self.payload['builder_key_string']
                         ['value'], 'hl-node')

    def test_call_census(self):
        census = self.payload['call_census']
        direct = census['direct_call_sites']
        self.assertEqual(direct['ctor_c'], [])
        self.assertEqual(direct['registrar_c'], [])
        self.assertEqual(
            [entry['site'] for entry in direct['lvl4_c']],
            ['0x2cd83a2'])
        self.assertEqual(
            [entry['site'] for entry in direct['lvl4_a']],
            ['0x2ae1a47', '0x2b40577'])
        self.assertEqual(
            [entry['site'] for entry in direct['lvl3_c']],
            ['0x2ae1eeb'])
        self.assertEqual(
            [entry['site'] for entry in direct['pre_4ab']],
            ['0x2ae2306'])
        self.assertEqual(
            [entry['site'] for entry in direct['call4a_b']],
            ['0x2453673'])
        for name in census['tail_call_sites'].values():
            self.assertEqual(name, [])
        self.assertEqual(census['lea_references']['ctor_c'],
                         ['0x2cef8f7'])

    def test_lvl4c_frame_census(self):
        census = self.payload['lvl4c_frame_census']
        self.assertEqual(
            census['buffer_stores'],
            {'0x5aa8': ['0x2ae179b', '0x2ae188d'],
             '0x5ab0': ['0x2ae17aa', '0x2ae1895']})
        self.assertEqual(census['hicopy_stores'], {})
        self.assertEqual(census['hicopy_loads'], {})
        self.assertEqual(census['entry_slot_stores'],
                         ['0x2ae16bf'])
        self.assertEqual(
            census['entry_slot_loads'],
            ['0x2ae1763', '0x2ae18ec', '0x2ae1947', '0x2ae19c7',
             '0x2ae1b1a', '0x2ae2794'])

    def test_small_census(self):
        census = self.payload['small_census']
        self.assertEqual(census['ctor_c']['stores'],
                         {'rsp': {'0x0': 2, '0x222': 1}})
        self.assertEqual(census['ctor_c']['leas'],
                         {'rsp': {'0x8': 1}})
        self.assertEqual(census['registrar_stub_c']['stores'],
                         {'rsp': {'0x0': 1}})

    def test_shaper_census(self):
        census = self.payload['shaper_census']
        for role in ('lvl4_a', 'lvl3_c'):
            stores = census[role]['stores']
            reg = 'rbx' if role == 'lvl4_a' else 'r13'
            # Exactly one +0x1e8 store per body: the rebuild's.
            self.assertEqual(stores[reg]['0x1e8'], 1)
            # The rebuild movups stores are the only stores
            # covering +0xc8..+0xf0.
            for off in ('0xc0', '0xd0', '0xe0', '0xf0'):
                self.assertEqual(stores[reg][off], 1)
            for off in ('0xc8', '0xd8', '0xe8', '0xf8'):
                self.assertNotIn(off, stores[reg])
            self.assertEqual(stores[reg]['0x248'], 8)
            self.assertEqual(stores[reg]['0x21a'], 5)
            self.assertEqual(census[role]['loads'][reg]['0xc8'],
                             18)

    def test_findings_records(self):
        producer = self.payload['phase_producer']
        self.assertIn('0x2ae19cc', producer['answer'])
        self.assertIn('0x2ae1b1f', producer['answer'])
        self.assertIn('0x6440b48', producer['boundary'])
        fields = self.payload['field_attribution']
        self.assertIn('0x2ae4604', fields['tag_0x248'])
        self.assertIn('0x2cde56b', fields['byte_0x1e8'])
        self.assertIn('hl-node', fields['sources_0xc8_0xf0'])
        b_side = self.payload['b_side']
        self.assertIn('0x2b40573', b_side['answer'])
        self.assertIn('0x2453622', b_side['answer'])
        self.assertIn('0x64e0a80',
                      self.payload['boundaries']['next_questions'])

    def test_byte_mutations_break_the_claims(self):
        cases = [
            (0x2AE19CC, 2),   # lvl4_c's copy-4 memcpy call
            (0x2CD8395, 0),   # ctor_c's dispatch-byte store
            (0x2B40573, 1),   # call4a_b's rdi = [rbp+0] load
            (0x2CEF902, 3),   # the stub's key-cell lea
        ]
        offset_base = 0x1000
        for va, skip in cases:
            mutated = bytearray(self.data)
            mutated[va - offset_base + skip] ^= 1
            with self.assertRaises(ValueError, msg=hex(va)):
                subject.analyze(bytes(mutated))

    def test_registrar_relocation_mutation_breaks_the_claims(self):
        mutated = bytearray(self.data)
        hit = None
        for section in sections(self.data):
            if section['name'] != '.rela.dyn':
                continue
            for i in range(section['offset'],
                           section['offset'] + section['size'], 24):
                off, _, _ = struct.unpack_from('<QQq', self.data, i)
                if off == 0x64E6C30:
                    hit = i + 16
        self.assertIsNotNone(hit)
        mutated[hit] ^= 1
        with self.assertRaises(ValueError):
            subject.analyze(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
