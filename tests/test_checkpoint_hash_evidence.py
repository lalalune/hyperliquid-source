"""Authenticate checkpoint hash evidence and reject structural corruption."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-checkpoint-hash-94'
spec = importlib.util.spec_from_file_location('checkpoint_hash_evidence', PACKET / 'verify.py')
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class CheckpointHashEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.layout = subject.Image(cls.data)

    def test_authenticated_record_and_complete_exports(self):
        self.assertEqual(subject.analyze(self.data), json.loads((PACKET / 'records.json').read_text()))
        self.assertEqual(subject.verify_exports(), 2 * len(subject.ANCHORS['ranges']))

    def test_each_selected_instruction_rejects_corruption(self):
        changed = bytearray(self.data)
        for row in subject.ANCHORS['facts']:
            with self.subTest(address=hex(row['address'])):
                offset = self.layout.offset(row['address'])
                changed[offset] ^= 1
                try:
                    with self.assertRaisesRegex(ValueError, 'instruction changed'):
                        subject.inspect(changed, self.layout)
                finally:
                    changed[offset] ^= 1

    def test_every_full_body_rejects_unselected_corruption(self):
        selected = set()
        for row in subject.ANCHORS['facts']:
            selected.update(range(row['address'], row['address'] + len(bytes.fromhex(row['bytes']))))
        changed = bytearray(self.data)
        for name, row in subject.ANCHORS['ranges'].items():
            with self.subTest(name=name):
                address = next(a for a in range(row['start'], row['end']) if a not in selected)
                offset = self.layout.offset(address)
                changed[offset] ^= 1
                try:
                    with self.assertRaisesRegex(ValueError, 'body changed'):
                        subject.inspect(changed, self.layout)
                finally:
                    changed[offset] ^= 1

    def test_all_metadata_ranges_reject_corruption(self):
        changed = bytearray(self.data)
        for row in subject.ANCHORS['metadata']:
            with self.subTest(name=row['name']):
                offset = self.layout.offset(row['address'])
                changed[offset] ^= 1
                try:
                    with self.assertRaisesRegex(ValueError, 'metadata changed'):
                        subject.inspect(changed, self.layout)
                finally:
                    changed[offset] ^= 1

    def test_each_relocation_component_rejects_corruption(self):
        changed = bytearray(self.data)
        for row in subject.ANCHORS['relocations']:
            for component in (0, 8, 16):
                with self.subTest(slot=hex(row['r_offset']), component=component):
                    offset = row['file_offset'] + component
                    changed[offset] ^= 1
                    try:
                        with self.assertRaisesRegex(ValueError, 'relocation changed'):
                            subject.inspect(changed, self.layout)
                    finally:
                        changed[offset] ^= 1

    def test_fde_and_export_metadata_cannot_drift(self):
        anchors = copy.deepcopy(subject.ANCHORS)
        anchors['ranges']['hash_helper']['end'] -= 1
        with self.assertRaisesRegex(ValueError, 'FDE changed'):
            subject.inspect(self.data, self.layout, anchors)
        for field, value in [('start', 0), ('sha256', '0' * 64), ('path', '../outside.txt')]:
            exports = copy.deepcopy(subject.EXPORTS)
            exports['exports'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                subject.verify_exports(exports)

    def test_dispatch_metadata_and_source_coordinates_cannot_drift(self):
        anchors = copy.deepcopy(subject.ANCHORS)
        table = next(row for row in anchors['metadata'] if row['name'] == 'finalize_dispatch')
        table['relative_i32_targets'][0] += 1
        with self.assertRaisesRegex(ValueError, 'dispatch target changed'):
            subject.inspect(self.data, self.layout, anchors)
        anchors = copy.deepcopy(subject.ANCHORS)
        location = next(row for row in anchors['metadata'] if row['name'] == 'update_source_location')
        location['line'] += 1
        with self.assertRaisesRegex(ValueError, 'source coordinate changed'):
            subject.inspect(self.data, self.layout, anchors)

    def test_both_disassemblers_cover_every_selected_instruction(self):
        for provider in ('gnu', 'llvm'):
            starts = set()
            for name in subject.ANCHORS['ranges']:
                text = (PACKET / 'native' / f'{name}.{provider}.txt').read_text()
                starts.update(int(match[1], 16) for match in
                              re.finditer(r'^\s*([0-9a-f]+):\s', text, re.M))
            self.assertTrue(all(row['address'] in starts for row in subject.ANCHORS['facts']))

    def test_structural_inspection_cannot_authenticate_input(self):
        self.assertEqual(subject.inspect(self.data, self.layout)['origin'],
                         'unqualified fixed-coordinate inspection')
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            subject.analyze(self.data[:-1])
        changed = bytearray(self.data)
        changed[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            subject.analyze(changed)


if __name__ == '__main__':
    unittest.main()
