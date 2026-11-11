"""Controls for the node #115 GetFileChecksumGenCrc32cFactory behaviour."""
import hashlib
import tempfile
from pathlib import Path
import unittest

from tools import file_checksum_get_factory115 as m


class GetFactoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        cls.checked = m.verify(cls.data)

    def alter(self, va, size, fn):
        secs = m.unique_sections(self.data)
        pos = m.file_offset(secs, va, size)
        original = bytes(self.data[pos:pos + size])
        try:
            self.data[pos] ^= 1
            with self.assertRaises(ValueError):
                fn(bytes(self.data))
        finally:
            self.data[pos:pos + size] = original

    def test_authentication_and_no_verify_on_bad_digest(self):
        m.authenticate(self.data)
        with self.assertRaises(ValueError):
            m.authenticate(b'not the target')

    def test_pinned_constants(self):
        self.assertEqual(m.COUNTS_CONST, 0x0000000100000001)
        self.assertEqual(m.COUNTS_CONST & 0xFFFFFFFF, 1)
        self.assertEqual(m.COUNTS_CONST >> 32, 1)
        self.assertEqual(m.FACTORY_VTABLE, 0x64D79B0)
        self.assertEqual(m.CONTROL_VTABLE, 0x64D7A90)
        self.assertEqual(m.FACTORY_SIZE, 0x20)
        self.assertEqual(m.CONTROL_SIZE, 0x18)
        self.assertEqual(m.GUARD_ADDR, 0x6508930)
        self.assertEqual(m.STATIC_PTR_ADDR, 0x6508940)
        self.assertEqual(m.STATIC_PI_ADDR, 0x6508948)
        self.assertEqual(m.DTOR_ADDR, 0x61CD720)

    def test_first_call_initialises(self):
        self.assertEqual(m.call_getter_model(m.fresh_state()),
                         ('A', 'B', 2, True, 'lock'))
        self.assertEqual(m.call_getter_model(m.fresh_state(threaded=True)),
                         ('A', 'B', 2, True, 'plain'))

    def test_repeated_gets_raise_use_count(self):
        for n in (1, 2, 3, 5, 10):
            result = m.run_sequence_model(m.fresh_state(), 'G' * n)
            self.assertEqual(result['final_use'], 1 + n)
            self.assertEqual(result['final_live'], n)
            self.assertEqual(result['init_runs'], 1)

    def test_get_then_release_returns_to_static_only(self):
        result = m.run_sequence_model(m.fresh_state(), 'GR')
        self.assertEqual(result['final_use'], 1)
        self.assertEqual(result['final_live'], 0)
        result = m.run_sequence_model(m.fresh_state(), 'GGGGGRRRRR')
        self.assertEqual(result['final_use'], 1)
        self.assertEqual(result['final_live'], 0)

    def test_already_initialised_skips_init(self):
        result = m.run_sequence_model(m.initialised_state(3), 'G')
        self.assertEqual(result['init_runs'], 1)
        self.assertEqual(result['final_use'], 5)
        result = m.run_sequence_model(m.initialised_state(0), 'GG')
        self.assertEqual(result['final_use'], 3)

    def test_defensive_empty_static_returns_null_pair(self):
        self.assertEqual(m.call_getter_model(m.defensive_empty_state()),
                         (None, None, 0, False, None))
        result = m.run_sequence_model(m.defensive_empty_state(), 'GG')
        self.assertEqual(result['final_use'], 0)
        self.assertEqual(result['init_runs'], 0)

    def test_release_with_no_live_copy_is_an_error(self):
        with self.assertRaises(ValueError):
            m.run_sequence_model(m.fresh_state(), 'R')
        with self.assertRaises(ValueError):
            m.run_sequence_model(m.initialised_state(0), 'R')

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            '43181e9223d6ee0a0c0b743900e8a4d2af98ffa3e9be6787892007b3e00c29a1')
        gets = sum(ops.count('G') for _, ops, _ in rows)
        releases = sum(ops.count('R') for _, ops, _ in rows)
        inits = sum(r['init_runs'] for _, _, r in rows)
        self.assertEqual((gets, releases, inits), (15754, 4714, 2117))

    def test_body_hash_matches_census(self):
        self.assertEqual(self.checked['body_hash'],
                         m.CENSUS_BODY['function'])
        self.assertEqual(self.checked['body_hash'],
                         '9016de75b9bb6c8723439a5a3ca9b4fba7e7d95bf20ef98cf508d51238e6c4df')

    def test_windows_reject_corruption(self):
        for label, start, end in m.WINDOWS:
            with self.subTest(window=label):
                self.alter(start, end - start, m.verify)

    def test_regenerated_packet_matches_committed(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'packet'
            m.generate(bytes(self.data), dest)
            for name in ('windows.tsv', 'cases.tsv',
                         'result.json', 'records.json'):
                committed = (m.PACKET / name).read_bytes()
                fresh = (dest / name).read_bytes()
                self.assertEqual(fresh, committed, name)


if __name__ == '__main__':
    unittest.main()
