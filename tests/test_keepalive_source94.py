"""Target-scoped integrity controls and independent protocol counterexamples."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import keepalive_source94 as k

PACKET = ROOT / 'research/work-items/RE-012-keepalive-source-94'
spec = importlib.util.spec_from_file_location('keepalive_relation', PACKET / 'protocol_relation.py')
relation = importlib.util.module_from_spec(spec); spec.loader.exec_module(relation)


class KeepaliveEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        cls.im = k.Image(cls.data)
        cls.golden = json.loads((PACKET / 'static/records.json').read_text())

    def rejects(self, data):
        try:
            actual = k.inspect(data, authenticate=False)
        except (ValueError, struct.error, UnicodeError, IndexError):
            return
        self.assertNotEqual(actual, self.golden, 'changed scoped evidence was silently accepted')

    def test_exact_regeneration(self):
        self.assertEqual(k.inspect(self.data), self.golden)
        self.assertEqual(sum(b['bytes'] for b in self.golden['bodies']), 7516)
        self.assertEqual(sum(b['instructions'] for b in self.golden['bodies']), 1616)

    def test_instruction_corruption_below_digest_gate(self):
        # Both durations, both unsigned clamps, retry tag, option levels/names,
        # failure predicates, zero return, errno packing, both real caller
        # enable gates and continuation/custom-drop predicates.
        addresses = [0x4ecd97c, 0x4ecd989, 0x4ecd994, 0x4ecd9a8, 0x4ecd9b9,
                     0x4ecd9be, 0x4ecd9d7, 0x4ecd9eb, 0x4ecda01, 0x4ecda1b,
                     0x4ecda2c, 0x4ecda31, 0x4ecda43, 0x4ecda47,
                     0x4ecda6c, 0x4ecdb21, 0x29af096, 0x29af0a5, 0x29af10f,
                     0x29af116, 0x29af127, 0x29af13a, 0x29af30e,
                     0x29c3397, 0x29c33b5, 0x29c33c0, 0x29c33df,
                     0x29c33f0, 0x29c3403, 0x29c3511, 0x29c3603]
        for va in addresses:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data); changed[self.im.offset(va)] ^= 1
                self.rejects(bytes(changed))

    def test_fde_and_source_record_corruption(self):
        for body in self.golden['bodies']:
            va = body['fde']['fde'] + 12
            changed = bytearray(self.data); changed[self.im.offset(va)] ^= 1
            self.rejects(bytes(changed))
        for record in self.golden['locations'] + self.golden['tracing_metadata']:
            changed = bytearray(self.data); changed[self.im.offset(int(record['path_va'], 16))] ^= 1
            self.rejects(bytes(changed))

    def test_relocation_corruption(self):
        for rec in self.golden['relocations']:
            with self.subTest(slot=rec['where']):
                changed = bytearray(self.data); changed[rec['file_offset'] + 16] ^= 1
                self.rejects(bytes(changed))

    def test_full_digest_gate(self):
        with self.assertRaises(k.EvidenceError):
            k.inspect(self.data[:-1])

    def test_boundaries_and_short_circuit(self):
        # Expectations below use direct literal event lists, separate from the
        # table relation. Values are artificial raw target-boundary probes.
        f = relation.fixture
        for n in [0, 1, 999999999, 1000000000, 1000000001, 0xffffffff]:
            record = f(t=0, s0=0x8000000000000000, n0=n, n1=1000000000)
            expected = [] if n == 1000000000 else [(6, 4, b'\xff\xff\xff\x7f', 4)]
            self.assertEqual(relation.requests(record), expected)
        for t in [0, 1, 2, 3, 0xffffffff]:
            expected = [(6, 6, b'\xff' * 4, 4)] if t == 1 else []
            self.assertEqual(relation.requests(f(t=t, n0=1000000000, n1=1000000000)), expected)
        for value, expected in [(0, 0), (0x7ffffffe, 0x7ffffffe), (0x7fffffff, 0x7fffffff),
                                (0x80000000, 0x7fffffff), (0xffffffffffffffff, 0x7fffffff)]:
            self.assertEqual(int.from_bytes(relation.requests(f(s0=value))[0][2], 'little'), expected)
        for failure in range(3):
            returns = [0, 0, 0]; returns[failure] = -1
            result = relation.helper(f(), returns, -1)
            self.assertEqual(len(result['requests']), failure + 1)
            self.assertEqual(result['rax'], 0xffffffff00000002)
            self.assertEqual(result['errno_reads'], 1)
        self.assertEqual(len(relation.helper(f(), [-2, 1, -2147483648], 1)['requests']), 3)
        self.assertEqual(relation.helper(f(), [-2, 1, -2147483648], 1)['rax'], 0)

    def test_registered_alternatives_and_corruption_controls(self):
        spec = importlib.util.spec_from_file_location('keepalive_verify', PACKET / 'verify.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
        expected = json.loads((PACKET / 'comparison/comparison.json').read_text())
        actual = verifier.registry_checks(registry, expected, self.golden)
        self.assertEqual((actual['target_intervals'], actual['alternative_comparisons']), (2, 4))
        labels = ['missing_alternative', 'changed_source_extent', 'changed_comparison_pointer',
                  'asserted_version_assignment', 'duplicate_target', 'changed_target_hash']
        for label in labels:
            with self.subTest(control=label):
                changed = copy.deepcopy(registry)
                row = next(r for r in changed['windows'] if r['id'] == 'node94-socket2-keepalive-4ecd970')
                if label == 'missing_alternative':
                    row['alternative_candidates'].pop()
                elif label == 'changed_source_extent':
                    row['alternative_candidates'][1]['source']['length'] -= 1
                elif label == 'changed_comparison_pointer':
                    row['alternative_candidates'][1]['comparison_pointer'][1] = 3
                elif label == 'asserted_version_assignment':
                    row['version_assignment_proved'] = True
                elif label == 'duplicate_target':
                    changed['windows'].append(copy.deepcopy(row))
                elif label == 'changed_target_hash':
                    row['target_body_sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    verifier.registry_checks(changed, expected, self.golden)

    def test_best_effort_counterexamples(self):
        for err in [0, 1, 11, 22, -1, -2147483648]:
            for failure in range(4):
                options = [0, 0, 0]
                if failure:
                    options[failure - 1] = -1
                result = relation.caller_stage(True, -1 if failure == 0 else 0,
                                               relation.fixture(), options, err)
                self.assertEqual(len(result['calls']), failure + 1)
                self.assertTrue(result['continues'])
                self.assertFalse(result['custom_drop'])
                self.assertEqual(result['error_word'], ((err & 0xffffffff) << 32) | 2)
        self.assertEqual(relation.caller_stage(False, -1, relation.fixture(), [-1] * 3, 22)['calls'], [])


if __name__ == '__main__':
    unittest.main()
