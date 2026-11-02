"""Selected node115 instruction routes, constructor closure and compiler admission."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import node115_snapshot_selectors_rust as subject


class Node115SelectorRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result=subject.oracle()

    def test_expected_corpus_precedes_production_and_keeps_release_and_denominators(self):
        frozen=json.loads((subject.PACKET/'FREEZE.json').read_text())
        self.assertFalse(frozen['production_source_exists'])
        self.assertEqual(frozen['target'],subject.native.SHA)
        self.assertEqual((self.result['count'],self.result['distinct_inputs']),(189952,189952))
        self.assertEqual(self.result['parts'],{'worker':108968,'wrapper':15420,'mode':28,'exit':65536})
        self.assertEqual(subject.sha(self.result['inputs']),frozen['input_sha256'])
        self.assertEqual(subject.sha(self.result['expected']),frozen['expected_sha256'])
        self.assertEqual(self.result['record'],json.loads((subject.PACKET/'native-records.json').read_text()))

    def test_raw_instruction_partition_and_actual_byte_controls_regenerate(self):
        self.assertEqual(len(self.result['selected_instructions']),90)
        self.assertEqual(self.result['selected_instructions'],
                         json.loads((subject.PACKET/'selected-instructions.json').read_text()))
        controls=json.loads(json.dumps(self.result['controls']))
        self.assertEqual(controls,json.loads((subject.PACKET/'native-controls.json').read_text()))
        self.assertEqual(len(controls),6)
        self.assertTrue(all(c['before']!=c['after'] and c['binding_rejected'] for c in controls))

    def test_local_adapter_has_only_actual_node115_slots_and_forbids_calls(self):
        data,image,_,blocker=subject.inspect(subject.TARGET)
        self.assertEqual(blocker['node94_specific_missing_slot'],'0x576f488')
        self.assertEqual(image.slots,subject.cpu.Image._slots(image))
        self.assertNotIn(subject.cpu.SLOT_NOTE,image.slots)
        m=subject.Machine(image)
        with self.assertRaisesRegex(ValueError,'call outside'):
            m.call(0,0)
        with self.assertRaisesRegex(ValueError,'memory outside'):
            m.load(subject.cpu.INPUT+64,1)
        with self.assertRaisesRegex(ValueError,'memory outside'):
            m.store(subject.cpu.INPUT,1,0)

    def test_known_exit_is_a_selected_guard_and_other_does_not_mean_a_call(self):
        inputs=self.result['inputs'].decode().splitlines()
        expected=self.result['expected'].decode().splitlines()
        exits={int(line.split('\t')[1]):answer for line,answer in zip(inputs,expected) if line.startswith('X\t')}
        self.assertEqual(len(exits),65536)
        self.assertEqual(sum(answer=='K' for answer in exits.values()),86)
        self.assertEqual(exits[0],'U')
        self.assertEqual(exits[266],'K')
        self.assertEqual(exits[351],'K')
        self.assertEqual(exits[352],'U')

    def test_smoke_fixtures_are_exact_native_rows_including_raw_width_boundaries(self):
        answers=dict(zip(self.result['inputs'].decode().splitlines(),
                         self.result['expected'].decode().splitlines()))
        rows=(subject.COMPONENT/'target-smoke.tsv').read_text().splitlines()
        self.assertEqual(len(rows),24)
        widths={'W':4,'O':5,'M':3,'X':2}
        for row in rows:
            f=row.split('\t');n=widths[f[0]]
            self.assertEqual(answers['\t'.join(f[:n])],'\t'.join(f[n:]))
        self.assertEqual(answers['O\t0\t9223372036854775809\t0\t4294967296'],'4\t0')

    def test_wrong_identity_and_wrong_expectations_stop_before_compiler(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);bad=root/'bad';bad.write_bytes(b'not node115')
            with mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler called')):
                with self.assertRaisesRegex(ValueError,'pinned node115 identity'):
                    subject.build(bad,root/'compiler',root/'new')
            self.assertFalse((root/'new').exists())
            changed=dict(self.result,expected=b'wrong\n')
            with mock.patch.object(subject,'oracle',return_value=changed), \
                 mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler called')):
                with self.assertRaisesRegex(ValueError,'frozen expectations differ'):
                    subject.build(bad,root/'compiler',root/'new')
