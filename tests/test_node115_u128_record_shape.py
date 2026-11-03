"""Malformed u128-to-binary64 records fail closed.

verify() dereferences the packet's records.json — the migration bounds,
the exact FDE, the body digest and the frozen-corpus digests — so a
record that is missing a field the function reads must meet the module's
ValueError diagnostics, not escape as a raw KeyError or TypeError.
Staging idiom follows test_node115_u128_binary64.py: the packet is
copied, PACKET/TARGET/SHA are patched to the packet's own body bytes,
the corpus digests are aligned to the staged packet files, and the ELF
seams (eh_frame_records/sections) return the packet's own rows so a
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
import node115_u128_binary64 as subject


class RecordShapeTests(unittest.TestCase):
    def verify_with(self, mutate):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            packet = base / 'packet'
            shutil.copytree(subject.PACKET, packet)
            pristine = json.loads((subject.PACKET / 'records.json').read_text())
            body = (packet / 'official-body.bin').read_bytes()
            record = json.loads((packet / 'records.json').read_text())
            record['inputs_sha256'] = hashlib.sha256((packet / 'inputs.tsv.gz').read_bytes()).hexdigest()
            record['expected_sha256'] = hashlib.sha256((packet / 'expected.tsv.gz').read_bytes()).hexdigest()
            mutate(record)
            (packet / 'records.json').write_text(json.dumps(record))
            target = base / 'node'
            target.write_bytes(body)
            fdes = [pristine['fde']]
            secs = [{'flags': 4, 'type': 1, 'address': subject.START,
                     'size': 1 << 20, 'offset': 0}]
            with patch.object(subject, 'PACKET', packet), \
                 patch.object(subject, 'TARGET', target), \
                 patch.object(subject, 'SHA', hashlib.sha256(body).hexdigest()), \
                 patch.object(subject, 'eh_frame_records', lambda data: (None, fdes)), \
                 patch.object(subject, 'sections', lambda data: secs):
                return subject.verify()

    def assert_record_rejected(self, mutate):
        with self.assertRaisesRegex(ValueError, 'Invalid u128 record'):
            self.verify_with(mutate)

    def test_well_formed_record_verifies(self):
        record = self.verify_with(lambda r: None)
        self.assertEqual((record['start'], record['end']), (subject.START, subject.END))

    def test_missing_start_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('start'))

    def test_missing_end_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('end'))

    def test_missing_fde_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('fde'))

    def test_missing_body_digest_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('body_sha256'))

    def test_missing_inputs_digest_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('inputs_sha256'))

    def test_missing_expected_digest_is_invalid_record(self):
        self.assert_record_rejected(lambda r: r.pop('expected_sha256'))

    def test_record_not_a_record_is_invalid_record(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            packet = base / 'packet'
            shutil.copytree(subject.PACKET, packet)
            (packet / 'records.json').write_text(json.dumps(['not', 'a', 'record']))
            body = (packet / 'official-body.bin').read_bytes()
            target = base / 'node'
            target.write_bytes(body)
            with patch.object(subject, 'PACKET', packet), \
                 patch.object(subject, 'TARGET', target), \
                 patch.object(subject, 'SHA', hashlib.sha256(body).hexdigest()):
                with self.assertRaisesRegex(ValueError, 'Invalid u128 record'):
                    subject.verify()


if __name__ == '__main__':
    unittest.main()
