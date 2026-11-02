"""Frozen three-lane control classification and compiler admission."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import snapshot_admission_rust as subject


class SnapshotRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result=subject.oracle()

    def test_production_rust_follows_the_frozen_three_lane_corpus(self):
        frozen=json.loads((subject.PACKET/'FREEZE.json').read_text())
        self.assertFalse(frozen['production_source_exists'])
        self.assertEqual((self.result['count'],self.result['distinct_inputs']),(240480,80160))
        self.assertEqual(subject.sha(self.result['inputs']),frozen['input_sha256'])
        self.assertEqual(subject.sha(self.result['expected']),frozen['expected_sha256'])
        self.assertEqual(self.result['record'],json.loads((subject.PACKET/'native-records.json').read_text()))

    def test_three_native_lanes_agree_without_claiming_three_distinct_input_spaces(self):
        expected=self.result['expected'].splitlines()
        self.assertEqual(len(expected),240480)
        self.assertEqual(expected[:80160],expected[80160:160320])
        self.assertEqual(expected[:80160],expected[160320:])

    def test_frozen_smoke_precedence_and_unsigned_edges_are_native(self):
        rows={}
        for line in self.result['inputs'].splitlines():
            f=tuple(map(int,line.split(b'\t')))
            if f[0]==0:rows[f]=None
        smoke=(subject.COMPONENT/'target-smoke.tsv').read_text().splitlines()
        self.assertEqual(len(smoke),14)
        mapping={'panic':'X','freeze':'F','periodic':'P','skip':'S'}
        data=(subject.ROOT/subject.native.BINARY).read_bytes()
        image=subject.native.Image(data)
        for line in smoke:
            fields=line.split('\t');args=tuple(map(int,fields[:4]))
            self.assertIn(args,rows)
            actual=subject.native.replay(image,subject.native.CASES[args[0]],*args[1:])
            self.assertEqual(mapping[actual],fields[4])

    def test_modified_expected_corpus_cannot_reach_the_compiler(self):
        changed=dict(self.result,expected=b'wrong\n')
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp)/'new'
            with mock.patch.object(subject,'oracle',return_value=changed), \
                 mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler called')):
                with self.assertRaisesRegex(ValueError,'frozen expectations differ'):
                    subject.build(Path(temp)/'input',Path(temp)/'compiler',out)
            self.assertFalse(out.exists())
