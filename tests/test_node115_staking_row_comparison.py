"""Target-bound static evidence controls; never evaluate captured instructions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-staking-row-comparison'
spec = importlib.util.spec_from_file_location('staking_row_comparison', PACKET / 'collect.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
MAX = (1 << 64) - 1


def mathematical_condition(selected, total):
    """Independent integer relation only; no native iterator/state model."""
    b, s = sum(selected), sum(total)
    return b <= MAX and s <= MAX and 2 * s < 3 * b


class StakingComparisonEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.record = json.loads((PACKET / 'records.json').read_text(encoding='utf-8'))

    def test_actual_target_and_complete_scopes(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), collector.SHA)
        self.assertEqual(len(self.record['windows']), 6)
        self.assertEqual(self.record['exported_bytes'], 3598)
        self.assertEqual(self.record['facts']['new_scope_bytes'], 2394)
        self.assertEqual(self.record['facts']['reused_caller_bytes'], 1204)
        self.assertEqual(self.record['implementation_bytes'], 0)
        self.assertEqual(self.record['requested_gates'], [])
        frames = (PACKET / 'frames.txt').read_text(encoding='utf-8')
        for window in self.record['windows']:
            start, end = int(window['start'], 16), int(window['end'], 16)
            _, body = collector.read(self.data, start, end - start)
            self.assertEqual(hashlib.sha256(body).hexdigest(), window['sha256'])
            self.assertIn('pc=' + format(start, '016x') + '..' + format(end, '016x'), frames)
            for value in window['unwind'].values():
                self.assertEqual(collector.read(self.data, int(value['va'], 16),
                                               len(bytes.fromhex(value['raw'])))[1].hex(),
                                 value['raw'])

    def test_actual_semantic_groups_and_relocation_bindings(self):
        self.assertEqual(collector.anchors(self.data), self.record['facts'])
        self.assertEqual(len(collector.CONFIG['anchors']), 69)
        bindings = {int(row['slot'], 16): row for row in self.record['bindings']}
        self.assertEqual(bindings[0x64dfb50]['symbol'], 'memcmp')
        self.assertEqual(bindings[0x64dfb50]['info'] & 0xffffffff, 6)
        self.assertEqual(bindings[0x64df830]['info'], 8)
        self.assertEqual(bindings[0x64df830]['addend'], '0x1680c10')
        self.assertIn({'slot': '0x6468cb0', 'path': 'l1/src/staking.rs',
                       'line': 185, 'column': 9},
                      [{k: row[k] for k in ('slot', 'path', 'line', 'column')}
                       for row in self.record['source_locations']])
        self.assertEqual(self.record['facts']['comparison']['result_register'],
                         'AL; upper RAX not normalized')

    def test_first_and_last_byte_of_each_group_rejected_without_digest_or_execution(self):
        mutated = bytearray(self.data)
        with mock.patch.object(collector.hashlib, 'sha256',
                               side_effect=AssertionError('Inner controls do not use the digest')):
            for address, raw in collector.CONFIG['anchors'].items():
                size = len(bytes.fromhex(raw))
                for delta in sorted({0, size - 1}):
                    offset, _ = collector.read(self.data, int(address, 16) + delta, 1)
                    with self.subTest(address=address, delta=delta):
                        mutated[offset] ^= 1
                        try:
                            with self.assertRaisesRegex(ValueError, 'changed native anchor'):
                                collector.anchors(mutated)
                        finally:
                            mutated[offset] ^= 1

    def test_wrong_target_rejected_before_native_query_or_output(self):
        mutated = bytearray(self.data)
        mutated[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'not-created'
            with mock.patch.object(collector.subprocess, 'check_output',
                                   side_effect=AssertionError('No native query allowed')):
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    collector.collect(mutated, output)
            self.assertFalse(output.exists())

    def test_damaged_truncated_and_duplicated_native_export_rows_rejected(self):
        start, end = 0x422e0f0, 0x422e273
        text = (PACKET / '422e0f0.objdump.txt').read_text(encoding='utf-8')
        _, body = collector.read(self.data, start, end - start)
        changed = text.replace('41 57', '41 56', 1)
        self.assertNotEqual(changed, text)
        with self.assertRaises(ValueError):
            collector.decode_export(changed, start, end, body)
        lines = text.splitlines()
        positions = [i for i, line in enumerate(lines)
                     if re.match(r'^\s*[0-9a-f]+:\s', line)]
        truncated = '\n'.join(line for i, line in enumerate(lines) if i != positions[-1]) + '\n'
        duplicated = '\n'.join(lines[:positions[0]] + [lines[positions[0]]] + lines[positions[0]:]) + '\n'
        for broken in (truncated, duplicated):
            with self.subTest(kind='truncated' if broken == truncated else 'duplicated'):
                with self.assertRaises(ValueError):
                    collector.decode_export(broken, start, end, body)

    def test_hand_derived_integer_witnesses(self):
        cases = json.loads((PACKET / 'math-witnesses.json').read_text(encoding='utf-8'))['cases']
        self.assertEqual(len(cases), 14)
        for case in cases:
            b, s = [int(x) for x in case['B']], [int(x) for x in case['S']]
            self.assertTrue(all(0 <= value <= MAX for value in b + s))
            with self.subTest(case=case['id']):
                self.assertEqual(mathematical_condition(b, s), case['expected'])

    def test_witnesses_distinguish_three_wrong_arithmetic_hypotheses(self):
        self.assertFalse(mathematical_condition([2], [2, 1]))
        self.assertTrue(2 * 3 <= 3 * 2)
        self.assertFalse(mathematical_condition([MAX], [MAX, 1]))
        self.assertTrue(2 * min(MAX + 1, MAX) < 3 * MAX)
        self.assertTrue(mathematical_condition([MAX], [MAX]))
        self.assertFalse(((2 * MAX) & MAX) < ((3 * MAX) & MAX))

    def test_complete_native_records_regenerate(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.assertEqual(collector.collect(self.data, output), self.record)
            for name in ['frames.txt', 'relocations.txt', 'records.json',
                         *[path.name for path in PACKET.glob('*.objdump.txt')]]:
                self.assertEqual((output / name).read_bytes(), (PACKET / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
