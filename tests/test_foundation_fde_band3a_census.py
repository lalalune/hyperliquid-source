'''Focused tests for the node #115 FDE-band census checker.'''
import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'foundation_fde_band3a_census.py'
SPEC = importlib.util.spec_from_file_location('foundation_fde_band3a_census', TOOL)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


@unittest.skipUnless(CHECKER.PACKET.is_dir(), 'packet is not written yet')
class FoundationFdeBand3aCensusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = CHECKER.verify()
        cls.evidence = json.loads((CHECKER.PACKET / 'evidence.json').read_text(encoding='utf-8'))
        cls.rows = CHECKER.band_frames(CHECKER.TARGET)
        cls.address, cls.offset, cls.size = CHECKER.text_section(CHECKER.TARGET)
        cls.window = (CHECKER.PACKET / 'window.txt').read_text(encoding='utf-8')

    def test_records_are_rederived_from_target(self):
        self.assertEqual(CHECKER.digest(CHECKER.TARGET), CHECKER.TARGET_SHA256)
        self.assertEqual(self.evidence['fde_count'], len(self.actual))
        self.assertTrue(self.actual)
        for record in self.actual:
            self.assertEqual(record[2], int(record[1], 16) - int(record[0], 16))
            self.assertGreater(record[4], 0)

    def test_band_records_are_ordered_and_disjoint(self):
        self.assertTrue(CHECKER.check_band(self.rows, self.address, self.size))
        self.assertEqual(len(self.rows), len(self.actual))
        starts = [row[0] for row in self.rows]
        self.assertEqual(starts, sorted(starts))
        self.assertEqual(len(set(starts)), len(starts))
        for previous, current in zip(self.rows, self.rows[1:]):
            self.assertLessEqual(previous[1], current[0])

    def test_rejects_reversed_record(self):
        bad = list(self.rows)
        start, end, line = bad[0]
        bad[0] = (end, start, line)
        with self.assertRaises(AssertionError) as caught:
            CHECKER.check_band(bad, self.address, self.size)
        self.assertIn('empty FDE range', str(caught.exception))

    def test_rejects_duplicate_start(self):
        bad = list(self.rows)
        bad[1] = (bad[0][0], bad[1][1], bad[1][2])
        with self.assertRaises(AssertionError):
            CHECKER.check_band(bad, self.address, self.size)

    def test_rejects_overlapping_record(self):
        bad = list(self.rows)
        bad[1] = (bad[0][1] - 1, bad[1][1], bad[1][2])
        with self.assertRaises(AssertionError) as caught:
            CHECKER.check_band(bad, self.address, self.size)
        self.assertIn('overlapping FDE range', str(caught.exception))

    def test_rejects_start_outside_band(self):
        bad = list(self.rows)
        bad[0] = (CHECKER.BAND_END + 0x10, bad[0][1], bad[0][2])
        with self.assertRaises(AssertionError) as caught:
            CHECKER.check_band(bad, self.address, self.size)
        self.assertIn('outside the band', str(caught.exception))

    def test_frames_come_from_target_fde_lines(self):
        self.assertEqual(len(self.rows), len(self.actual))
        for (start, end, line), record in zip(self.rows, self.actual):
            self.assertIn('FDE cie=', line)
            self.assertEqual(('0x%x' % start), record[0])
            self.assertEqual(('0x%x' % end), record[1])

    def test_rejects_fabricated_frames(self):
        lines = [line for start, end, line in self.rows]
        self.assertTrue(CHECKER.validate_frames('\n'.join(lines) + '\n', self.rows))
        with self.assertRaises(AssertionError):
            CHECKER.validate_frames('\n'.join(lines[:-1]) + '\n', self.rows)

    def test_rejects_reordered_frames(self):
        lines = [line for start, end, line in self.rows]
        lines[0], lines[1] = lines[1], lines[0]
        with self.assertRaises(AssertionError):
            CHECKER.validate_frames('\n'.join(lines) + '\n', self.rows)

    def test_window_prologue_matches_target_bytes(self):
        smallest = min(self.actual, key=lambda item: item[2])
        self.assertTrue(CHECKER.validate_window(self.window, smallest))

    def test_rejects_changed_window_prologue(self):
        smallest = min(self.actual, key=lambda item: item[2])
        bad = self.window.replace('41 57', '00 00', 1)
        self.assertNotEqual(bad, self.window)
        with self.assertRaises(AssertionError):
            CHECKER.validate_window(bad, smallest)

    def test_rejects_missing_window(self):
        smallest = min(self.actual, key=lambda item: item[2])
        with self.assertRaises(AssertionError):
            CHECKER.validate_window('', smallest)

    def test_smallest_record_body_bytes_match_saved_digest(self):
        smallest = min(self.actual, key=lambda item: item[2])
        start = int(smallest[0], 16)
        end = int(smallest[1], 16)
        self.assertGreaterEqual(start, self.address)
        self.assertLessEqual(end, self.address + self.size)
        self.assertEqual(end - start, smallest[2])
        with CHECKER.TARGET.open('rb') as handle:
            handle.seek(self.offset + start - self.address)
            body = handle.read(end - start)
        self.assertEqual(len(body), smallest[2])
        self.assertEqual(hashlib.sha256(body).hexdigest(), smallest[3])

    def test_instruction_count_is_rederived(self):
        record = self.actual[0]
        start = int(record[0], 16)
        end = int(record[1], 16)
        self.assertEqual(CHECKER.instruction_count(CHECKER.TARGET, start, end), record[4])
        self.assertGreater(record[4], 1)

    def test_accepts_the_saved_packet_records(self):
        self.assertTrue(CHECKER.validate(self.actual, copy.deepcopy(self.evidence)))

    def test_rejects_tampered_digest(self):
        bad = copy.deepcopy(self.evidence)
        bad['fdes'][len(bad['fdes']) // 2][3] = '0' * 64
        with self.assertRaises(AssertionError):
            CHECKER.validate(self.actual, bad)

    def test_rejects_changed_saved_end(self):
        bad = copy.deepcopy(self.evidence)
        index = len(bad['fdes']) // 2
        bad['fdes'][index][1] = hex(int(bad['fdes'][index][1], 16) - 1)
        with self.assertRaises(AssertionError):
            CHECKER.validate(self.actual, bad)

    def test_rejects_changed_saved_size(self):
        bad = copy.deepcopy(self.evidence)
        bad['fdes'][0][2] += 1
        with self.assertRaises(AssertionError) as caught:
            CHECKER.validate(self.actual, bad)
        self.assertIn('fde byte length mismatch', str(caught.exception))

    def test_rejects_tampered_instruction_count(self):
        bad = copy.deepcopy(self.evidence)
        bad['fdes'][0][4] += 1
        with self.assertRaises(AssertionError):
            CHECKER.validate(self.actual, bad)

    def test_rejects_zero_instruction_count(self):
        bad = copy.deepcopy(self.evidence)
        bad['fdes'][1][4] = 0
        with self.assertRaises(AssertionError) as caught:
            CHECKER.validate(self.actual, bad)
        self.assertIn('fde instruction count mismatch', str(caught.exception))

    def test_rejects_tampered_end(self):
        bad = copy.deepcopy(self.evidence)
        bad['fdes'][-1][1] = hex(int(bad['fdes'][-1][1], 16) + 1)
        with self.assertRaises(AssertionError):
            CHECKER.validate(self.actual, bad)

    def test_rejects_fabricated_start(self):
        bad = copy.deepcopy(self.evidence)
        bad['fdes'][3][0] = hex(int(bad['fdes'][3][0], 16) + 0x10)
        with self.assertRaises(AssertionError):
            CHECKER.validate(self.actual, bad)

    def test_rejects_duplicate_record(self):
        bad = copy.deepcopy(self.evidence)
        bad['fdes'].append(copy.deepcopy(bad['fdes'][-1]))
        with self.assertRaises(AssertionError):
            CHECKER.validate(self.actual, bad)

    def test_verify_rejects_corrupted_saved_record(self):
        path = CHECKER.PACKET / 'evidence.json'
        original = path.read_bytes()
        try:
            evidence = json.loads(original.decode('utf-8'))
            evidence['fdes'][0][3] = '0' * 64
            path.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
            with self.assertRaises(AssertionError):
                CHECKER.verify()
        finally:
            path.write_bytes(original)
        self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
