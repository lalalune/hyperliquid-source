"""Real two-capture graph correspondence and below-identity byte controls."""
from pathlib import Path
import os
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import kind5_release_drift as drift


class ReleaseDriftEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = [ROOT / f'artifacts/node/{release}/hl-node' for release in ['94', '115']]
        if any(not p.is_file() or (p.stat().st_size < 256 and p.read_bytes().startswith(
                b'version https://git-lfs.github.com/spec/v1\n')) for p in cls.paths):
            raise unittest.SkipTest('materialize both authenticated Git LFS captures')
        if not shutil.which('objdump') or not (
                os.environ.get('LLVM_OBJDUMP') or shutil.which('llvm-objdump')):
            raise unittest.SkipTest('existing GNU and LLVM decoders required for fresh evidence')
        try:
            drift.k.native_tools()
        except drift.k.bv.EvidenceError as error:
            raise unittest.SkipTest(str(error)) from error
        cls.temp = tempfile.TemporaryDirectory(prefix='kind5-drift-test-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.output = Path(cls.temp.name) / 'evidence'
        cls.result = drift.collect(cls.paths, cls.output, controls=True)

    def test_complete_correspondence_denominator(self):
        result = self.result
        self.assertEqual(result['candidate_counts'], {'reader': 3, 'wrapper': 4, 'error': 1})
        self.assertEqual((result['matched_count'], result['rejected_lookalikes']), (4, 4))
        self.assertEqual((result['paired_instructions'], result['paired_bytes']), (238, 788))
        self.assertEqual(result['node115_sha256'], drift.PIN115)
        self.assertFalse(result['captured_execution'])
        self.assertFalse(result['node115_fixture_evaluation'])
        self.assertFalse(result['gate_requested'])

    def test_same_prefix_does_not_admit_sibling_readers(self):
        records = {r['node115_fde'][0]: r for r in self.result['comparisons']}
        for start in ['0x5822490', '0x58225c0', '0x2cd7ac0', '0x5821250']:
            with self.subTest(start=start):
                self.assertFalse(records[start]['matched'])
                self.assertTrue(records[start]['reason'])

    def test_actual_instruction_table_and_relocation_mutations_rejected(self):
        controls = self.result['semantic_controls']
        self.assertEqual({c['name'] for c in controls},
                         {'kind-literal', 'table-order', 'callee-relocation', 'table-RIP', 'branch-byte'})
        self.assertEqual(len({c['sha256'] for c in controls}), 5)
        for control in controls:
            with self.subTest(control=control['name']):
                self.assertTrue(control['rejected'])
                self.assertTrue(control['global_identity_deliberately_bypassed'])
                self.assertNotEqual(control['before'], control['after'])
                self.assertNotEqual(control['sha256'], drift.PIN115)
                self.assertNotIn('identity', control['reason'])

    def test_slot_aliases_are_recorded_per_reference(self):
        wrappers = [r for r in self.result['comparisons'] if r['role'] == 'wrapper' and r['matched']]
        self.assertEqual({r['node115_fde'][0] for r in wrappers}, {'0x2cd7bb0', '0x5821340'})
        slots = {d['slot'] for r in wrappers for d in r['node115_dependencies']
                 if d['kind'] == 'relative-slot' and d['role'] == 'error'}
        self.assertEqual(slots, {'0x64e7f78', '0x64e7f88'})
        self.assertEqual({d['target'] for r in wrappers for d in r['node115_dependencies']
                          if d['kind'] == 'relative-slot' and d['role'] == 'error'}, {'0x5822700'})

    def test_wrong_capture_refused_before_output(self):
        altered = Path(self.temp.name) / 'wrong.elf'
        altered.write_bytes(b'not the captured image')
        output = Path(self.temp.name) / 'must-not-exist'
        with self.assertRaisesRegex(drift.k.bv.EvidenceError, 'artifact identity'):
            drift.collect([self.paths[0], altered], output)
        self.assertFalse(output.exists())

    def test_existing_evidence_not_overwritten(self):
        before = (self.output / 'observations.json').read_bytes()
        with self.assertRaisesRegex(drift.k.bv.EvidenceError, 'output exists'):
            drift.collect(self.paths, self.output, controls=True)
        self.assertEqual((self.output / 'observations.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
