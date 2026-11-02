"""Frozen raw metadata/IEEE predicates and target-grounded compiler admission."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import gossip_reload_rust as subject


class GossipReloadRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result=subject.oracle()

    def test_frozen_inputs_cover_both_native_gates_before_production_rust(self):
        frozen=json.loads((subject.PACKET/'FREEZE.json').read_text())
        self.assertFalse(frozen['production_source_exists'])
        self.assertEqual((self.result['count'],self.result['distinct_inputs']),(17133,17133))
        self.assertEqual(subject.sha(self.result['inputs']),frozen['input_sha256'])
        self.assertEqual(subject.sha(self.result['expected']),frozen['expected_sha256'])
        self.assertEqual(self.result['record'],json.loads((subject.PACKET/'native-records.json').read_text()))
        self.assertEqual((len(subject.metadata_inputs()),len(subject.throttle_inputs())),(16649,484))

    def test_smoke_answers_come_from_native_corpus_and_include_zero_nan_case(self):
        answers=dict(zip(self.result['inputs'].decode().splitlines(),
                         self.result['expected'].decode().splitlines()))
        smoke=(subject.COMPONENT/'target-smoke.tsv').read_text().splitlines()
        self.assertEqual(len(smoke),18)
        for line in smoke:
            source,answer=line.rsplit('\t',1)
            self.assertEqual(answers[source],answer)
        self.assertEqual(answers['T\t0\t7ff8000000000000\t7ff8000000000000'],'1')
        self.assertEqual(answers['T\t1\t7ff8000000000000\t0000000000000000'],'0')

    def test_nan_corpus_is_qualified_quiet_nan_not_a_signalling_exception_claim(self):
        nan_words=set()
        for _,helper,threshold in subject.throttle_inputs():
            for bits in (helper,threshold):
                exponent=(bits>>52)&0x7ff
                fraction=bits&((1<<52)-1)
                if exponent==0x7ff and fraction:
                    self.assertTrue(fraction&(1<<51))
                    nan_words.add(bits)
        self.assertEqual(len(nan_words),3)

    def test_changed_oracle_is_rejected_before_compiler(self):
        changed=dict(self.result,expected=b'wrong\n')
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp)/'new'
            with mock.patch.object(subject,'oracle',return_value=changed), \
                 mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler called')):
                with self.assertRaisesRegex(ValueError,'frozen expectations differ'):
                    subject.build(Path(temp)/'input',Path(temp)/'compiler',out)
            self.assertFalse(out.exists())
