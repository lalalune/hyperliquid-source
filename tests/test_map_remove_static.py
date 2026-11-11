"""Native target evidence and map-remove counterfactuals."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import map_remove_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-map-remove')


class MapRemoveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or \
                subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs = sections(cls.data)
        cls.report = subject.analyze(cls.data)

    def offset(self, va):
        s = next(s for s in self.secs
                 if s['type'] != 8
                 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutate(self, va, value=None):
        b = bytearray(self.data)
        o = self.offset(va)
        b[o] = b[o] ^ 1 if value is None else value
        return bytes(b)

    def test_analysis_shape(self):
        owners = {row['role'] for row in self.report['owners']}
        self.assertEqual(owners, {'marked_cleanup', 'map_drop'})
        boundaries = {row['role'] for row in self.report['boundaries']}
        self.assertEqual(boundaries, {
            'map_lookup', 'wrap_ctor', 'pad_helper_next', 'map_grow',
            'sibling_grow', 'map_insert', 'insert_helper'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        cleanup = next(r for r in self.report['owners']
                       if r['role'] == 'marked_cleanup')
        self.assertEqual(cleanup['start'], '0x47425c0')
        self.assertEqual(cleanup['end'], '0x4742676')
        self.assertEqual(cleanup['bytes'], 182)
        self.assertEqual(
            cleanup['sha256'],
            'a27501e59ce2fa4fc610ed13d3da63c01ea578963bec73d983d86b584a3e49e4')
        drop = next(r for r in self.report['owners']
                    if r['role'] == 'map_drop')
        self.assertEqual(drop['start'], '0x4742960')
        self.assertEqual(drop['bytes'], 307)
        self.assertEqual(
            drop['sha256'],
            '1aae44edc7f846da821541c9455706506403ae72981926a7927dd0aa0a3069e1')

    def test_slot_bindings(self):
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')
        self.assertEqual(bindings['grow_fn']['addend'], '0x4742aa0')
        self.assertEqual(bindings['sibling_grow_fn']['addend'],
                         '0x4743990')

    def test_grow_reference_census(self):
        census = self.report['grow_reference_census']
        self.assertEqual(census['direct_e8_e9'], [])
        self.assertEqual(census['slot_ff15_ff25'], ['0x474ba06'])
        self.assertEqual(census['riprel_all_forms']['0x4742aa0'], [])
        self.assertEqual(census['riprel_all_forms']['0x64eaf78'],
                         ['0x474ba06'])
        self.assertEqual(census['rela_addend']['.rela.dyn'],
                         [{'slot': '0x64eaf78', 'type': 8}])
        self.assertEqual(census['rela_addend']['.rela.plt'], [])
        self.assertEqual(len(census['absolute_qword_body']), 1)
        self.assertEqual(census['absolute_qword_body'][0]['section'],
                         '.rela.dyn')
        self.assertEqual(len(census['absolute_qword_slot']), 1)

    def test_erase_candidate_censuses(self):
        censuses = self.report['erase_candidate_censuses']
        self.assertEqual(len(censuses['fnv_bodies']), 20)
        self.assertEqual(censuses['fnv_bodies_cluster'],
                         ['0x4741960', '0x4742130', '0x4742aa0',
                          '0x474b620'])
        self.assertEqual(censuses['imm80_store_tied_bodies'], [])
        self.assertEqual(censuses['tzcnt_bsr_bytestore_bodies'],
                         ['0x143f000', '0x63bb7e0'])
        self.assertEqual(censuses['mov80_imul58_bodies_cluster'], [])
        imm = censuses['cluster_imm_stores']
        self.assertTrue(all(not v['imm80'] for v in imm.values()))
        self.assertEqual(imm['0x4742aa0']['immff'],
                         ['0x474320c', '0x4743211'])
        self.assertEqual(imm['0x47425c0']['immff'],
                         ['0x4742623', '0x474262b'])

    def test_caller_census(self):
        callers = self.report['caller_census']
        self.assertEqual(callers['marked_cleanup'],
                         [['0x4743fdd', '0xe8']])
        self.assertEqual(len(callers['map_drop']), 6)
        self.assertEqual(callers['map_lookup'],
                         [['0x4740368', '0xe8'], ['0x4740745', '0xe8']])

    def test_layouts(self):
        self.assertEqual(len(self.report['cleanup_phases']), 4)
        self.assertEqual(len(self.report['drop_phases']), 4)
        self.assertIn('removal_side', self.report['verdicts'])
        self.assertIn('grow_reachability', self.report['verdicts'])

    def test_counterfactual_cleanup_items_dec(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474263d))

    def test_counterfactual_cleanup_store_ff(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x4742627))

    def test_counterfactual_drop_tzcnt(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x47429fe))

    def test_counterfactual_grow_slot_call(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474ba07))

    def test_counterfactual_cleanup_caller(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x4743fde))

    def test_generate_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            subject.generate(subject.TARGET, out)
            got = json.loads((out / 'records.json').read_text())
            self.assertEqual(got['verdicts'], self.report['verdicts'])
            self.assertTrue(
                (out / 'marked_cleanup_objdump.txt').is_file())
            self.assertTrue((out / 'map_drop_objdump.txt').is_file())
            self.assertTrue((out / 'frames.txt').is_file())

    def test_committed_records_match(self):
        committed = PACKET / 'records.json'
        if not committed.is_file():
            raise unittest.SkipTest('packet not generated yet')
        got = json.loads(committed.read_text())
        self.assertEqual(got, self.report)


if __name__ == '__main__':
    unittest.main()
