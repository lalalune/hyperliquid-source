"""Byte-key search evidence and actual operand counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import db_hub_key_static as subject


class DbHubKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('wrong capture')
        cls.report = subject.analyze(cls.data)

    def mutate(self, address, raw):
        value = bytearray(self.data)
        offset = subject.reader(value)[1](address, len(raw))[0]
        value[offset:offset + len(raw)] = raw
        return value

    def test_full_native_body_and_retained_record(self):
        self.assertEqual(self.report, json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual((self.report['bytes'], self.report['instructions']), (841, 199))
        self.assertEqual([x['line'] for x in self.report['source_locations']], [62, 68, 66])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            subject.generate(subject.TARGET, output)
            for path in output.iterdir():
                self.assertEqual(path.read_bytes(), (subject.PACKET / path.name).read_bytes())

    def test_all_byte_queries_against_sorted_key_boundary_sets(self):
        p = self.report['parameters']
        for keys in [[], [0], [255], [0, 127, 128, 255], list(range(256))]:
            for query in range(256):
                expected = next((i for i, key in enumerate(keys) if key >= query), len(keys))
                self.assertEqual(subject.local_scan(p, keys, query),
                                 {'index': expected, 'equal': expected < len(keys) and keys[expected] == query})
        self.assertEqual((p['count_offset'], p['key_biased_offset'], p['child_offset'], p['value_offset']),
                         (0x62, 0x65, 0x70, 8))

    def test_actual_continuation_operand_changes_search_relation(self):
        data = self.mutate(0x1692d64, b'\x00')
        original = self.report['parameters']
        changed = subject.parameters(data)
        self.assertEqual(subject.local_scan(original, [1, 5], 5), {'index': 1, 'equal': True})
        self.assertEqual(subject.local_scan(changed, [1, 5], 5), {'index': 0, 'equal': False})
        self.assertNotEqual(subject.analyze(data), self.report)

    def test_layout_branch_call_and_location_changes_are_visible(self):
        for address in [0x1692d27, 0x1692d4f, 0x1692d91, 0x1692d9b, 0x1692d86]:
            offset = subject.reader(self.data)[1](address, 1)[0]
            changed = self.mutate(address, bytes([self.data[offset] ^ 1]))
            self.assertNotEqual(subject.parameters(changed), self.report['parameters'])
        # Actual child-depth underflow displacement, selected path operation call,
        # and relocated source line each affect independent recorded evidence.
        for address, value, key in [(0x1692d89, b'\xde', 'branches'),
                                    (0x1692e03, b'\xf8', 'calls'),
                                    (0x64089e0 + 16, struct.pack('<I', 67), 'source_locations')]:
            self.assertNotEqual(subject.analyze(self.mutate(address, value))[key], self.report[key])

    def test_identity_rejection_precedes_output_creation(self):
        for data in [b'not a target', self.data[:-1], self.mutate(0x1692d64, b'\x00')]:
            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'input'
                output = Path(directory) / 'output'
                target.write_bytes(data)
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    subject.generate(target, output)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
