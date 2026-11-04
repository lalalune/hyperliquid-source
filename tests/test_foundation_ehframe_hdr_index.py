"""Committed checks for the RE-001-node115-ehframe-hdr-index evidence packet.

Runs the real checker ``tools/foundation_ehframe_hdr_index.py`` against the
pinned node #115 capture (read in place, never copied, never executed) and
against the packet files saved under
``research/work-items/RE-001-node115-ehframe-hdr-index/``.
"""
import contextlib
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_ehframe_hdr_index as subject


class EhFrameHdrIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target = Path(subject.TARGET)
        if not target.is_file() or target.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = target.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.TARGET_SHA256:
            raise ValueError('wrong node115 capture')
        cls.derived = subject.derive_records(cls.data)
        cls.recorded = json.loads(subject.read_packet_text('evidence.json'))

    def test_real_checker_entry_accepts_saved_packet(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            status = subject.main([])
        self.assertEqual(status, 0)
        self.assertTrue(out.getvalue().strip().endswith('OK'))

    def test_derive_json_cli_prints_the_same_record(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            status = subject.main(['--derive-json'])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(out.getvalue()), self.derived)

    def test_saved_records_equal_the_derived_bytes(self):
        subject.compare(self.derived, self.recorded)
        subject.check_excerpts(self.derived)
        subject.corruption_control(self.derived, self.recorded)

    def test_header_encodings_decode_from_the_pinned_bytes(self):
        header = self.derived['eh_frame_hdr']
        frame = self.derived['eh_frame']
        self.assertEqual(header['version'], 1)
        self.assertEqual(header['eh_frame_ptr_enc'], '0x1b')
        self.assertEqual(header['fde_count_enc'], '0x03')
        self.assertEqual(header['table_enc'], '0x3b')
        raw = bytes.fromhex(header['header_hex'])
        base = int(header['va'], 16)
        pointer, cursor = subject.encoded(raw, 4, int(header['eh_frame_ptr_enc'], 16), base + 4, base)
        self.assertEqual(hex(pointer), header['eh_frame_ptr'])
        self.assertEqual(pointer, int(frame['va'], 16))
        self.assertTrue(header['eh_frame_ptr_matches_section'])
        count, cursor = subject.encoded(raw, cursor, int(header['fde_count_enc'], 16), base + cursor, base)
        self.assertEqual(count, header['fde_count'])
        self.assertEqual(hex(base + cursor), header['table_va'])

    def test_index_covers_the_fde_set(self):
        header = self.derived['eh_frame_hdr']
        frame = self.derived['eh_frame']
        index = self.derived['index']
        self.assertEqual(index['entries'], header['fde_count'])
        self.assertEqual(index['entries'], frame['fde_records'])
        self.assertEqual(frame['nonzero_start_records'], frame['fde_records'])
        self.assertEqual(index['duplicate_starts'], 0)
        self.assertEqual(index['missing_fde_starts'], 0)
        self.assertEqual(index['index_only_starts'], 0)
        self.assertTrue(index['monotonic_strict'])
        self.assertEqual(header['file_offset'], header['va'])
        self.assertEqual(frame['file_offset'], frame['va'])
        self.assertEqual(len(index['slice']), subject.SLICE)
        self.assertEqual(len(index['slice_hex']), subject.SLICE * 16)
        self.assertEqual(hashlib.sha256(bytes.fromhex(index['slice_hex'])).hexdigest(), index['slice_sha256'])
        self.assertEqual(index['first_start'], index['slice'][0]['start'])

    def test_extent_ends_come_from_the_fde_pc_range(self):
        ends = self.derived['ends_from_fde']
        self.assertEqual(ends['records_checked'], subject.SLICE)
        self.assertEqual(ends['positive_ranges'], subject.SLICE)
        self.assertEqual(ends['start_mismatches'], 0)
        self.assertEqual(ends['end_differs_from_next_index_start'], subject.SLICE - 1)

    def test_readme_records_the_same_facts(self):
        text = subject.read_packet_text('README.md')
        header = self.derived['eh_frame_hdr']
        frame = self.derived['eh_frame']
        index = self.derived['index']
        needles = (subject.TARGET_SHA256, '{:,}'.format(self.derived['target']['size']),
                   header['va'], header['file_offset'], header['table_va'],
                   '{:,}'.format(header['size']), frame['va'], frame['file_offset'],
                   '{:,}'.format(frame['size']), header['header_hex'], header['header_sha256'],
                   str(header['fde_count']), index['first_start'], index['last_start'],
                   index['slice_hex'], index['slice_sha256'])
        for needle in needles:
            self.assertIn(needle, text)

    def test_corrupted_derived_values_are_rejected(self):
        cases = (('eh_frame_hdr', 'version'), ('eh_frame_hdr', 'fde_count'),
                 ('eh_frame_hdr', 'table_va'), ('eh_frame', 'fde_records'),
                 ('eh_frame', 'size'), ('index', 'slice_sha256'),
                 ('index', 'last_start'), ('ends_from_fde', 'end_differs_from_next_index_start'))
        for section, key in cases:
            broken = json.loads(json.dumps(self.derived))
            value = broken[section][key]
            broken[section][key] = value + 1 if isinstance(value, int) else 'x' + str(value)
            with self.assertRaises(AssertionError, msg='%s.%s' % (section, key)):
                subject.compare(broken, self.recorded)

    def test_missing_or_changed_saved_values_are_rejected(self):
        cases = (('eh_frame_hdr', 'fde_count'), ('eh_frame_hdr', 'header_sha256'),
                 ('index', 'slice_sha256'), ('index', 'slice'),
                 ('ends_from_fde', 'records_checked'))
        for section, key in cases:
            removed = json.loads(json.dumps(self.recorded))
            del removed[section][key]
            with self.assertRaises(AssertionError, msg='missing %s.%s' % (section, key)):
                subject.compare(self.derived, removed)
            changed = json.loads(json.dumps(self.recorded))
            value = changed[section][key]
            changed[section][key] = value + 1 if isinstance(value, int) else 'x' + str(value)
            with self.assertRaises(AssertionError, msg='changed %s.%s' % (section, key)):
                subject.compare(self.derived, changed)

    def test_corrupted_excerpts_are_rejected(self):
        packet = Path(subject.PACKET)
        with tempfile.TemporaryDirectory() as tmp:
            for name in ('header.txt', 'index.txt'):
                shutil.copyfile(packet / name, Path(tmp) / name)
            with mock.patch.object(subject, 'PACKET', tmp):
                subject.check_excerpts(self.derived)
                for name in ('header.txt', 'index.txt'):
                    path = Path(tmp) / name
                    saved = path.read_bytes()
                    self.assertGreater(len(saved), 2)
                    path.write_bytes(saved[:-2] + bytes([saved[-2] ^ 1]) + saved[-1:])
                    with self.assertRaises(AssertionError, msg=name):
                        subject.check_excerpts(self.derived)
                    path.write_bytes(saved)


if __name__ == '__main__':
    unittest.main()
