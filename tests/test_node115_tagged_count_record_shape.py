"""Malformed tagged-count records fail closed.

verify() dereferences the packet's records.json — the target/body/fixture
digests, the window rows and the case count — so a record that is missing
a field the function reads must meet the module's ValueError diagnostics,
not escape as a raw KeyError or TypeError. Staging idiom follows
test_node115_tagged_count.py: the packet is copied, PACKET/TARGET/SHA are
patched to staged bytes whose digest the record is aligned to, and the
ELF seams (eh_frame_records/sections) return the packet's own rows so a
well-formed record verifies end to end.
"""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_tagged_count as subject


class RecordShapeTests(unittest.TestCase):
    def verify_with(self, mutate):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            packet = base / 'packet'
            shutil.copytree(subject.PACKET, packet)
            pristine = json.loads((subject.PACKET / 'records.json').read_text())
            body = bytes.fromhex((packet / 'body.hex').read_text())
            size = max(r['file_offset'] for r in pristine['windows']) + len(body)
            blob = bytearray(size)
            for row in pristine['windows']:
                blob[row['file_offset']:row['file_offset'] + len(body)] = body
            blob = bytes(blob)
            record = json.loads((packet / 'records.json').read_text())
            record['target_sha256'] = hashlib.sha256(blob).hexdigest()
            record['fixture_sha256'] = hashlib.sha256((packet / 'vectors.tsv').read_bytes()).hexdigest()
            mutate(record)
            (packet / 'records.json').write_text(json.dumps(record))
            target = base / 'node'
            target.write_bytes(blob)
            fdes = [r['fde'] for r in pristine['windows']]
            secs = [{'flags': 4, 'type': 1, 'address': r['start'],
                     'size': r['end'] - r['start'], 'offset': r['file_offset']}
                    for r in pristine['windows']]
            with patch.object(subject, 'PACKET', packet), \
                 patch.object(subject, 'TARGET', target), \
                 patch.object(subject, 'SHA', hashlib.sha256(blob).hexdigest()), \
                 patch.object(subject, 'eh_frame_records', lambda data: (None, fdes)), \
                 patch.object(subject, 'sections', lambda data: secs):
                return subject.verify()

    def assert_record_rejected(self, mutate):
        with self.assertRaisesRegex(ValueError, 'Invalid tagged-count record'):
            self.verify_with(mutate)

    def test_well_formed_record_verifies(self):
        record = self.verify_with(lambda r: None)
        self.assertEqual(len(record['windows']), 3)

    def test_missing_target_digest_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('target_sha256'))

    def test_missing_body_digest_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('body_sha256'))

    def test_missing_windows_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('windows'))

    def test_missing_fixture_digest_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('fixture_sha256'))

    def test_missing_cases_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('cases'))

    def test_window_row_missing_start_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r['windows'][0].pop('start'))

    def test_window_row_missing_end_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r['windows'][0].pop('end'))

    def test_window_row_missing_fde_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r['windows'][0].pop('fde'))

    def test_window_row_missing_file_offset_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r['windows'][0].pop('file_offset'))

    def test_windows_not_a_list_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.update(windows='xyz'))

    def test_window_row_not_a_record_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r['windows'].__setitem__(0, 'row'))


if __name__ == '__main__':
    unittest.main()
