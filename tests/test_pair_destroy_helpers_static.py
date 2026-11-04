"""Native target evidence and pair-destroy counterfactuals."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import pair_destroy_helpers_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-pair-destroy-helpers')


class PairDestroyHelpersTests(unittest.TestCase):
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
        self.assertEqual(owners, {'vec_a_pair_destroy',
                                  'reader_pair_destroy'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        by_role = {row['role']: row for row in self.report['owners']}
        self.assertEqual(by_role['vec_a_pair_destroy']['bytes'], 130)
        self.assertEqual(
            by_role['vec_a_pair_destroy']['sha256'],
            '30ce062b876d862e3961d70031ed434c3e520457bc3c16900e1b6fafa6a4511a')
        self.assertEqual(
            by_role['reader_pair_destroy']['sha256'],
            'ae6e68cf8978e52df9dda3f1d2849d62d09fa99f0f880c04137413d82a93a12d')
        boundaries = {row['role'] for row in self.report['boundaries']}
        self.assertEqual(len(boundaries), 8)
        self.assertIn('vec_a_record_destructor', boundaries)
        self.assertIn('reader_record_destructor', boundaries)

    def test_slot_bindings(self):
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['dealloc']['slot'], '0x64df4a0')
        self.assertEqual(bindings['dealloc']['type'], 8)
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')

    def test_transfer_census(self):
        transfers = self.report['transfers']
        self.assertEqual(transfers['vec_a_pair_destroy']['call_sites'],
                         ['0x153df83'])
        self.assertEqual(transfers['reader_pair_destroy']['call_sites'],
                         ['0x474e973'])
        self.assertEqual(
            transfers['vec_a_subvec_drain_unwind']['call_sites'],
            ['0x15386a3', '0x1538f92'])
        self.assertEqual(
            transfers['reader_subvec_drain_unwind']['call_sites'],
            ['0x474dc56', '0x474dda2'])
        for name, rows in transfers.items():
            self.assertEqual(rows['jmp_sites'], [], name)
        owners = {r['site']: r['owner_fde']
                  for r in transfers['vec_a_pair_destroy']['call_rows']}
        self.assertEqual(owners['0x153df83'],
                         ['0x153deb0', '0x153df9b'])
        owners = {r['site']: r['owner_fde'] for r in
                  transfers['reader_subvec_drain_unwind']['call_rows']}
        self.assertEqual(owners['0x474dc56'],
                         ['0x474dba0', '0x474dc86'])

    def test_clone_shape(self):
        shape = self.report['shapes'][0]
        self.assertEqual(shape['instructions'], 44)
        self.assertTrue(shape['masked_identical'])
        diffs = shape['differences']
        self.assertEqual(len(diffs), 3)
        self.assertEqual([d['offset'] for d in diffs],
                         ['0x41', '0x74', '0x7d'])
        self.assertEqual([d['kind'] for d in diffs],
                         ['ripdisp32', 'ripdisp32', 'rel32'])
        self.assertEqual([d['a_target'] for d in diffs],
                         ['0x64df4a0', '0x64df4a0', '0x63f0a50'])
        for d in diffs:
            self.assertEqual(d['a_target'], d['b_target'])

    def test_caller_shapes(self):
        shapes = self.report['caller_shapes']
        self.assertEqual([s['role'] for s in shapes], [
            'vec_a_element_drop', 'reader_element_drop',
            'vec_a_record_destructor', 'reader_record_destructor'])
        self.assertEqual([s['header_offset'] for s in shapes],
                         ['0x18', '0x18', '0x18', '0x0'])
        self.assertEqual([s['normal_free']['form'] for s in shapes],
                         ['tail_jump', 'tail_jump', 'call',
                          'tail_jump'])
        self.assertEqual(
            [s['pad_before_drain']['wrapper_target'] for s in shapes],
            ['0x1539990', '0x474e270', '0x1539990', '0x474e270'])
        self.assertEqual([s['drain_target'] for s in shapes],
                         ['0x153deb0', '0x474e8a0', '0x153deb0',
                          '0x474e8a0'])

    def test_counterfactual_helper_body(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x1537B25))

    def test_counterfactual_helper_pin(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474E0C6))

    def test_counterfactual_census_site(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x153DF83))

    def test_counterfactual_caller_pin(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x1538F28))

    def test_generate_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            subject.generate(subject.TARGET, out)
            got = json.loads((out / 'records.json').read_text())
            self.assertEqual(got, self.report)
            for name in ('vec_a_pair_destroy', 'reader_pair_destroy',
                         'vec_a_element_drop', 'reader_element_drop',
                         'vec_a_record_destructor',
                         'reader_record_destructor'):
                self.assertTrue((out / f'{name}_objdump.txt').is_file())
            self.assertTrue((out / 'frames.txt').is_file())

    def test_committed_records_match(self):
        committed = PACKET / 'records.json'
        if not committed.is_file():
            raise unittest.SkipTest('packet not generated yet')
        got = json.loads(committed.read_text())
        self.assertEqual(got, self.report)


if __name__ == '__main__':
    unittest.main()
