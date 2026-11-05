import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tools')]

import packet_x5_stored_pointer_readers as packet

PACKET_DIR = ROOT / 'research/work-items' / packet.WORK_ITEM
DATA = packet.TARGET.read_bytes() if packet.TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == packet.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == packet.TARGET_SHA256)

# The seven stored bodies (H31's zero-direct-caller set), their
# slots, forms, bases and headers -- all re-derived by analyze().
EXPECTED = {
    '0x159d600': {'slot': '0x63ff748', 'form': 'header',
                  'base': '0x63ff730', 'drop': '0x15a9c50',
                  'size': 3744, 'align': 8, 'run': 1,
                  'after': '0x448bd0',
                  'reader': '0x15d0660', 'lea_site': '0x15d089d',
                  'class': 'materialise_into_constructed_record',
                  'record': {'record_stack_base': '0x58',
                             'record_size': 0x128,
                             'field_offset': '0x30'}},
    '0x17457f0': {'slot': '0x640e920', 'form': 'header',
                  'base': '0x640e908', 'drop': '0x174d9c0',
                  'size': 3744, 'align': 8, 'run': 1,
                  'after': '0x448bd0',
                  'reader': '0x16d7df0', 'lea_site': '0x16d8171',
                  'class': 'materialise_into_constructed_record',
                  'record': {'record_stack_base': '0x68',
                             'record_size': 0x128,
                             'field_offset': '0x30'}},
    '0x2a225c0': {'slot': '0x64455e0', 'form': 'header',
                  'base': '0x64455c8', 'drop': '0x29eadd0',
                  'size': 2208, 'align': 16, 'run': 1,
                  'after': '0x4349eb',
                  'reader': '0x2d062f0', 'lea_site': '0x2d06804',
                  'class': 'store_and_direct_dispatch',
                  'record': None},
    '0x2a2a0e0': {'slot': '0x6445880', 'form': 'header',
                  'base': '0x6445868', 'drop': '0x29ea680',
                  'size': 2224, 'align': 16, 'run': 1,
                  'after': '0x4349eb',
                  'reader': '0x2d087e0', 'lea_site': '0x2d090a2',
                  'class': 'store_and_direct_dispatch',
                  'record': None},
    '0x2a64e20': {'slot': '0x64462b0', 'form': 'header',
                  'base': '0x6446298', 'drop': '0x2aa31b0',
                  'size': 3744, 'align': 8, 'run': 1,
                  'after': '0x448bd0',
                  'reader': '0x294f1a0', 'lea_site': '0x294f3dd',
                  'class': 'materialise_into_constructed_record',
                  'record': {'record_stack_base': '0x58',
                             'record_size': 0x128,
                             'field_offset': '0x30'}},
    '0x5a93b50': {'slot': '0x64b9b70', 'form': 'slot_base',
                  'base': '0x64b9b70', 'drop': None,
                  'size': None, 'align': None, 'run': 7,
                  'after': '0x5a97c60',
                  'reader': '0x5964ef0', 'lea_site': '0x5964f64',
                  'class': 'materialise_into_constructed_record',
                  'record': {'record_stack_base': '0x80',
                             'record_size': 0x200,
                             'field_offset': '0x10'}},
    '0x5a940c0': {'slot': '0x64ba390', 'form': 'slot_base',
                  'base': '0x64ba390', 'drop': None,
                  'size': None, 'align': None, 'run': 7,
                  'after': '0x5a97cb0',
                  'reader': '0x5965d90', 'lea_site': '0x5965e04',
                  'class': 'materialise_into_constructed_record',
                  'record': {'record_stack_base': '0x80',
                             'record_size': 0x200,
                             'field_offset': '0x10'}},
}

DISPATCH_CALL_SITES = {'0x2d0681e', '0x2d090c3'}


@unittest.skipUnless(MATERIALISED, 'node 115 artifact is not materialised')
class X5StoredPointerReadersPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = packet.analyze(DATA)

    def test_regeneration_matches_retained_records(self):
        retained = json.loads((PACKET_DIR / 'records.json').read_text())
        self.assertEqual(self.records, retained)

    def test_source_pin(self):
        source = self.records['source']
        self.assertEqual(source['slot'], '0x64e7718')
        self.assertEqual(source['stored_body_count'], 7)
        self.assertEqual(source['work_item'],
                         'RE-005-node115-x5-consumer-callers')
        bodies = {e['body']['start'] for e in self.records['stored']}
        self.assertEqual(bodies, set(EXPECTED))

    def test_slots_and_forms(self):
        for e in self.records['stored']:
            exp = EXPECTED[e['body']['start']]
            self.assertEqual(e['slot'], exp['slot'])
            self.assertEqual(e['slot_section'], '.data.rel.ro')
            self.assertEqual(e['relocation']['type'], 8)
            self.assertEqual(e['relocation']['addend'],
                             e['body']['start'])
            self.assertEqual(e['relocation']['offset'], e['slot'])
            self.assertEqual(e['form'], exp['form'])
            self.assertEqual(e['base'], exp['base'])
            self.assertEqual(e['method_run'], exp['run'])
            self.assertEqual(e['entry_after_slot']['kind'],
                             'relocation')
            self.assertEqual(e['entry_after_slot']['addend'],
                             exp['after'])
            if exp['form'] == 'header':
                self.assertIsNone(e['preceding_triple'])
                self.assertEqual(e['header']['drop'], exp['drop'])
                self.assertEqual(e['header']['size'], exp['size'])
                self.assertEqual(e['header']['align'], exp['align'])
                self.assertEqual(
                    e['entry_after_slot']['addend_section'], '.rodata')
                self.assertEqual(
                    int(e['slot'], 16) - int(e['base'], 16), 0x18)
            else:
                self.assertIsNone(e['header'])
                self.assertEqual(e['base'], e['slot'])
                self.assertEqual(
                    e['entry_after_slot']['addend_section'], '.text')
                self.assertEqual(len(e['preceding_triple']), 3)

    def test_exactly_one_reader_each(self):
        census = self.records['census']
        self.assertEqual(census['stored_bodies'], 7)
        self.assertEqual(census['references_to_bases'], 7)
        self.assertEqual(census['reader_bodies'], 7)
        self.assertEqual(census['direct_references_to_slots'], 2)
        self.assertTrue(census['all_references_are_lea'])
        readers = set()
        for e in self.records['stored']:
            exp = EXPECTED[e['body']['start']]
            self.assertEqual(len(e['readers']), 1)
            r = e['readers'][0]
            readers.add(r['body']['start'])
            self.assertEqual(r['body']['start'], exp['reader'])
            self.assertEqual(r['lea_site'], exp['lea_site'])
            self.assertTrue(r['lea_insn'].startswith('lea '),
                            r['lea_insn'])
            self.assertTrue(
                int(r['body']['start'], 16) <= int(r['lea_site'], 16)
                < int(r['body']['end'], 16), r['lea_site'])
            self.assertEqual(r['classification'], exp['class'])
            self.assertEqual(r['record'], exp['record'])
        self.assertEqual(len(readers), 7)

    def test_use_forms(self):
        dispatch_sites = set()
        for e in self.records['stored']:
            r = e['readers'][0]
            stores = [u for u in r['uses'] if u['kind'] == 'store_value']
            self.assertEqual(len(stores), 1, r['lea_site'])
            through = [u for u in r['uses']
                       if u['kind'] == 'mem_through'
                       and u['reads_stored_pointer']]
            if r['classification'] == 'store_and_direct_dispatch':
                self.assertEqual(len(through), 1)
                self.assertEqual(through[0]['effective'], e['slot'])
                self.assertIn('call', through[0]['insn'])
                dispatch_sites.add(through[0]['site'])
            else:
                self.assertEqual(through, [])
                self.assertIsNotNone(r['record'])
        self.assertEqual(dispatch_sites, DISPATCH_CALL_SITES)

    def test_no_other_path(self):
        census = self.records['census']
        self.assertEqual(
            census['relocations_with_addend_eq_any_slot_or_base'], 0)
        self.assertEqual(
            census['stored_qword_copies_of_slots_or_bases_outside_rela'],
            0)
        self.assertEqual(
            census['imm_materialisations_of_slots_or_bases'], 0)
        self.assertEqual(
            census['dynsym_entries_with_slot_or_base_st_value'], 0)

    def test_one_level_up_counts(self):
        # The two dispatch readers are themselves reached only via
        # a stored pointer each; the five constructors have exactly
        # one raw direct caller each.
        for e in self.records['stored']:
            r = e['readers'][0]
            if r['classification'] == 'store_and_direct_dispatch':
                self.assertEqual(r['direct_callers'], 0)
                self.assertEqual(r['relocation_addends'], 1)
            else:
                self.assertEqual(r['direct_callers'], 1)
                self.assertEqual(r['relocation_addends'], 0)

    def test_frames_match_regeneration(self):
        retained = (PACKET_DIR / 'frames.txt').read_text()
        regenerated = '\n'.join(
            packet.frames_lines(DATA, self.records)) + '\n'
        self.assertEqual(regenerated, retained)
        self.assertEqual(len(retained.strip().split('\n')), 14)

    def test_manifest_hashes(self):
        manifest = (PACKET_DIR / 'MANIFEST.sha256').read_text()
        for line in manifest.strip().split('\n'):
            digest, name = line.split('  ')
            raw = (PACKET_DIR / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest,
                             name)


if __name__ == '__main__':
    unittest.main()
