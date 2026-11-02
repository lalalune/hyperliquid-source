"""Fourteen actual conversion windows, proof bindings and compiler admission."""
import hashlib,json
from pathlib import Path
import subprocess,sys,tempfile,unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import cumulative_minute_rust as subject
class CumulativeMinuteRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=subject.native.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.native.SHA256:raise ValueError('wrong target')
        cls.image=subject.cpu.Image(cls.data);cls.bindings=subject.bind(cls.image)
    def test_full_native_bindings_and_division_proof_remain_identical(self):
        record=subject.native.analyze(self.data)
        self.assertEqual(record,json.loads((subject.PACKET/'native-records.json').read_text()))
        self.assertEqual(len(record['conversions']),14)
        f=json.loads((subject.PACKET/'FREEZE.json').read_text())
        self.assertFalse(f['production_source_exists'])
        self.assertEqual((f['distinct_raw_inputs'],f['native_comparisons'],f['native_windows']),(4594,64316,14))
    def test_actual_raw_window_partitions_and_frozen_smoke(self):
        self.assertEqual(self.bindings,json.loads((subject.PACKET/'window-bindings.json').read_text()))
        rows=(subject.PACKET/'target-smoke.tsv').read_text().splitlines();self.assertEqual(len(rows),14)
        self.assertEqual((subject.PACKET/'target-smoke.tsv').read_bytes(),(subject.COMPONENT/'target-smoke.tsv').read_bytes())
        for block in self.bindings:
            for row in rows:
                f=row.split('\t');self.assertEqual(subject.evaluate(self.image,block,int(f[0]))[0],'\t'.join(f[1:]))
    def test_actual_operand_controls_change_outputs_and_fail_bindings(self):
        for c in json.loads((subject.PACKET/'native-controls.json').read_text()):
            changed=bytearray(self.data);off=self.image.file_offset(int(c['va'],16));self.assertEqual(changed[off],c['old']);changed[off]=c['new'];private=subject.cpu.Image(bytes(changed))
            self.assertEqual(subject.evaluate(self.image,self.bindings[0],c['raw_input'])[0],c['before'])
            self.assertEqual(subject.evaluate(private,self.bindings[0],c['raw_input'])[0],c['after'])
            self.assertNotEqual(c['before'],c['after'])
            with self.assertRaisesRegex(ValueError,'selected conversion changed'):subject.native.analyze(changed)
    def test_no_calls_or_output_writes_in_local_conversion(self):
        m=subject.Machine(self.image)
        with self.assertRaisesRegex(ValueError,'calls forbidden'):m.call(0)
        with self.assertRaisesRegex(ValueError,'spills forbidden'):m.spill(subject.cpu.INPUT,0,4)
        with self.assertRaisesRegex(ValueError,'outside raw input word'):m.reload(0,subject.cpu.INPUT+4,1)
    def test_bad_capture_stops_before_compiler_or_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);bad=root/'bad';bad.write_bytes(b'wrong capture')
            with mock.patch.object(subprocess,'check_output',side_effect=AssertionError('compiler called')):
                with self.assertRaisesRegex(ValueError,'pinned node94 identity'):subject.build(bad,root/'rustc',root/'out')
            self.assertFalse((root/'out').exists())
