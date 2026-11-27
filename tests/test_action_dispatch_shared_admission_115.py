import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import action_dispatch_shared_admission_115 as T  # noqa: E402


class SharedAdmissionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = T.TARGET.read_bytes()
        cls.rows = T.load_rows()

    def test_all_router_handlers_are_pinned(self):
        result = T.verify_records(self.data, self.rows)
        self.assertEqual(result['handlers'], 92)
        self.assertEqual(result['common_first_calls'], 92)
        self.assertEqual(result['both_check_calls'], 92)
        self.assertGreaterEqual(result['pinned_calls'], 92 * 5)

    def test_literal_markers_keep_exceptions_visible(self):
        result = T.verify_records(self.data, self.rows)
        self.assertEqual(result['handlers_with_literal_0x120_store'], 88)
        self.assertEqual(result['handlers_with_literal_0x0f_tag_store'], 92)
        self.assertEqual(result['handlers_without_literal_0x120_store'], [
            '0x2c0ede0', '0x2c1fd40', '0x2c06530', '0x2c0a610',
        ])

    def test_existing_model_maps_to_ten_router_entries(self):
        result = T.verify_records(self.data, self.rows)
        self.assertEqual(result['exact_clone_model_indices'], [84, 1, 27, 21, 45, 55, 80, 6, 25, 8])

    def test_digest_damage_is_rejected(self):
        with self.assertRaises(T.EvidenceError):
            T.verify_records(self.data[:-1], self.rows)

    def test_missing_handler_is_rejected(self):
        with self.assertRaises(T.EvidenceError):
            T.verify_records(self.data, self.rows[:-1])

    def test_router_index_mutation_is_rejected(self):
        damaged = [dict(row) for row in self.rows]
        damaged[0]['tag'] = '0x87'
        with self.assertRaises(T.EvidenceError):
            T.verify_records(self.data, damaged)

    def test_call_displacement_mutation_is_rejected(self):
        damaged = bytearray(self.data)
        row = self.rows[0]
        site_s, kind, target_s = row['calls_to_second_gate'].split(',')[0].split(':')
        site, target = int(site_s, 16), int(target_s, 16)
        text = next(s for s in T.sections(self.data) if s['name'] == '.text')
        offset = site - text['address'] + text['offset'] + 1
        damaged[offset] ^= 1
        with self.assertRaisesRegex(T.EvidenceError, 'call target mismatch'):
            T.verify_call(bytes(damaged), text, site, kind, target)

    def test_result_marker_mutation_is_rejected(self):
        damaged = bytearray(self.data)
        row = next(row for row in self.rows if row['code120_sites'] != '-')
        site_s, expected_hex = row['code120_sites'].split(':')
        site, expected = int(site_s, 16), bytes.fromhex(expected_hex)
        text = next(s for s in T.sections(self.data) if s['name'] == '.text')
        offset = site - text['address'] + text['offset']
        damaged[offset + 4] ^= 1
        with self.assertRaisesRegex(T.EvidenceError, 'marker bytes differ'):
            T.verify_marker(bytes(damaged), text, site, expected, '0x120 store')


if __name__ == '__main__':
    unittest.main()
