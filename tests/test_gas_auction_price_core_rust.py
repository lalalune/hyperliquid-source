"""Helper-free price projection, frozen native corpus and safety boundaries."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import gas_auction_price_core_rust as subject

class GasPriceCoreRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.result=subject.oracle()

    def test_frozen_population_and_complete_owner_bindings(self):
        f=json.loads((subject.PACKET/'FREEZE.json').read_text())
        self.assertFalse(f['production_source_exists']);self.assertEqual(f['helper_calls'],0)
        self.assertFalse(f['signalling_nan_included'])
        self.assertEqual(self.result['rows'],8312)
        self.assertEqual(subject.sha(self.result['inputs']),f['input_sha256'])
        self.assertEqual(subject.sha(self.result['expected']),f['expected_sha256'])
        self.assertEqual(self.result['owner'],json.loads((subject.PACKET/'owner.json').read_text()))
        self.assertEqual((self.result['owner']['bytes'],self.result['owner']['instructions'],self.result['owner']['visited_instructions']),(652,149,92))

    def test_frozen_smoke_and_own_copy_are_native_results(self):
        answers=dict(zip(self.result['inputs'].decode().splitlines(),self.result['expected'].decode().splitlines()))
        rows=(subject.PACKET/'target-smoke.tsv').read_text().splitlines()
        self.assertEqual(len(rows),13)
        self.assertEqual((subject.COMPONENT/'target-smoke.tsv').read_bytes(),(subject.PACKET/'target-smoke.tsv').read_bytes())
        for row in rows:
            f=row.split('\t');self.assertEqual(answers['\t'.join(f[:4])],'\t'.join(f[4:]))

    def test_actual_borrow_and_wrapped_add_controls_change_outputs(self):
        controls=json.loads(json.dumps(self.result['controls']))
        self.assertEqual(controls,json.loads((subject.PACKET/'native-controls.json').read_text()))
        self.assertEqual(len(controls),2)
        self.assertTrue(all(c['before']!=c['after'] for c in controls))

    def test_plain_engine_has_no_substituted_helpers_and_restricts_memory(self):
        engine=subject.Engine(subject.native.load_image())
        self.assertEqual(engine.m.calls,{})
        self.assertEqual(engine.m.slots,{})
        self.assertEqual(engine.m.memory.statics,{})
        with self.assertRaisesRegex(ValueError,'outside selected memory'):
            engine.m.memory.write(subject.native.AUCTION,8,0)
        with self.assertRaisesRegex(ValueError,'outside selected memory'):
            engine.m.memory.read(subject.native.OUT+16,1)

    def test_wrong_capture_is_rejected_before_compiler_or_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);bad=root/'bad';bad.write_bytes(b'not the node')
            with mock.patch.object(subprocess,'check_output',side_effect=AssertionError('compiler called')):
                with self.assertRaises(subject.native.EvidenceError):
                    subject.build(bad,root/'rustc',root/'out')
            self.assertFalse((root/'out').exists())
