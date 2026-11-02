"""Raw signed pair widths, saved/capped distinction and actual byte controls."""
import hashlib,json
from pathlib import Path
import subprocess,sys,tempfile,unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import node115_latency_pair_rust as subject
class LatencyPairRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.result=subject.oracle()
    def test_full_native_records_and_pre_rust_finite_population(self):
        f=json.loads((subject.PACKET/'FREEZE.json').read_text())
        self.assertFalse(f['production_source_exists']);self.assertEqual(f['helper_calls'],0)
        self.assertEqual((f['rows'],f['distinct_signed_pairs'],f['lanes']),(2468,1234,2))
        self.assertEqual(subject.sha(self.result['inputs']),f['input_sha256']);self.assertEqual(subject.sha(self.result['expected']),f['expected_sha256'])
        self.assertEqual(self.result['record'],json.loads((subject.PACKET/'native-records.json').read_text()))
        self.assertEqual(self.result['selected_instructions'],json.loads((subject.PACKET/'selected-instructions.json').read_text()))
    def test_exact_instruction_widths_and_signed32_regression(self):
        self.assertEqual(self.result['conversions'],json.loads((subject.PACKET/'conversion-bindings.json').read_text()))
        self.assertEqual(sorted(c['source_bytes'] for c in self.result['conversions']),[4,4,8,8])
        engine=subject.Engine(subject.generic.Image(subject.native.TARGET.read_bytes()))
        self.assertEqual(engine.run(0,-1,-2147483648)[0],'0')
        self.assertEqual(engine.run(0,-1,1000000001)[0],str(subject.generic.to_bits(1e-9)))
        self.assertEqual(engine.m.calls,{});self.assertEqual(engine.m.slots,{});self.assertEqual(engine.m.memory.statics,{})
        with self.assertRaisesRegex(ValueError,'outside qualified'):engine.m.memory.write(subject.generic.HEAP_BASE,8,0)
    def test_smoke_keeps_uncapped_saved_value_and_raw_bit_results(self):
        answers=dict(zip(self.result['inputs'].decode().splitlines(),self.result['expected'].decode().splitlines()));rows=(subject.PACKET/'target-smoke.tsv').read_text().splitlines();self.assertEqual(len(rows),18)
        self.assertEqual((subject.COMPONENT/'target-smoke.tsv').read_bytes(),(subject.PACKET/'target-smoke.tsv').read_bytes())
        for row in rows:
            f=row.split('\t');self.assertEqual(answers['\t'.join(f[:3])],'\t'.join(f[3:]))
        self.assertEqual(answers['1\t120\t0'],f'{subject.generic.to_bits(60.0)}\t{subject.generic.to_bits(120.0)}')
    def test_real_divisor_cap_and_correction_controls(self):
        c=json.loads(json.dumps(self.result['controls']));self.assertEqual(c,json.loads((subject.PACKET/'native-controls.json').read_text()))
        self.assertEqual(len(c),3);self.assertTrue(all(x['before']!=x['after'] and x['binding_rejected'] for x in c))
    def test_wrong_capture_stops_before_compiler_or_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);bad=root/'bad';bad.write_bytes(b'not node115')
            with mock.patch.object(subprocess,'check_output',side_effect=AssertionError('compiler called')):
                with self.assertRaisesRegex(ValueError,'pinned node115 identity'):subject.build(bad,root/'rustc',root/'out')
            self.assertFalse((root/'out').exists())
