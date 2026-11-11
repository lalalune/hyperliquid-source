"""Controls for the node #115 ROCKSDB_XXH64 one-shot function."""
import hashlib
import random
import tempfile
from pathlib import Path
import unittest

from tools import xxh64_oneshot115 as m


class XXH64OneshotTests(unittest.TestCase):
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

    def test_xxh64_check_values(self):
        # Published XXH64 vectors anchor the model and the reference.
        self.assertEqual(m.xxh64_model(b'', 0), 0xEF46DB3751D8E999)
        self.assertEqual(m.xxh64_model(b'a', 0), 0xD24EC4F1A98C6E5B)
        self.assertEqual(m.xxh64_model(b'abc', 0), 0x44BC2CF5AD770999)
        self.assertEqual(m.xxh64_reference(b'', 0), 0xEF46DB3751D8E999)
        self.assertEqual(m.xxh64_reference(b'a', 0), 0xD24EC4F1A98C6E5B)
        self.assertEqual(m.xxh64_reference(b'abc', 0), 0x44BC2CF5AD770999)
        # Computed values both implementations agree on.
        self.assertEqual(m.xxh64_model(b'123456789', 0), 0x8CB841DB40E6AE83)
        self.assertEqual(m.xxh64_model(bytes(range(32)), 0),
                         0xCBF59C5116FF32B4)
        self.assertEqual(m.xxh64_model(bytes(range(33)), 0),
                         0x0C535D1ACAFB8EAD)
        self.assertEqual(m.xxh64_model(bytes(range(64)), 1),
                         0x3CE5BDF7575926C0)
        self.assertEqual(m.xxh64_model(bytes(0xAB for _ in range(1024)), 0),
                         0x31C5118D25963EC5)
        self.assertEqual(m.xxh64_model(b'', 1), 0xD5AFBA1336A3BE4B)

    def test_null_branch(self):
        # Null input: h = seed + P5 + n, avalanche, no buffer load.
        self.assertEqual(m.xxh64_null(0, 0), 0xEF46DB3751D8E999)
        self.assertEqual(m.xxh64_null(0, 9), 0xD5DD67EC9A0B4DFA)
        # The null rule with length 0 is the empty-input value.
        self.assertEqual(m.xxh64_null(1, 0), m.xxh64_model(b'', 1))
        # ... and differs from the non-null value for the same length.
        self.assertNotEqual(m.xxh64_null(0, 9),
                            m.xxh64_model(b'\x00' * 9, 0))

    def test_model_matches_references_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            'cceb1459ff06f7a0c738d43b2c2453880a36604fb6b01195babdad808f556365')

    def test_streaming_chunked_feeds(self):
        rng = random.Random(20261109)
        for length in (0, 1, 31, 32, 33, 64, 65, 100, 1024):
            data = bytes(rng.randrange(256) for _ in range(length))
            for seed in (0, 1, 0x0123456789ABCDEF):
                stream = m.XXH64Stream(seed)
                # Feed byte-by-byte on short inputs, in thirds otherwise.
                step = 1 if length < 64 else max(1, length // 3)
                for i in range(0, length, step):
                    stream.update(data[i:i + step])
                self.assertEqual(stream.digest(),
                                 m.xxh64_model(data, seed))

    def test_prime_immediates_and_p1p2(self):
        secs = m.unique_sections(self.data)
        for name, site, value in m.PRIME_SITES:
            self.assertEqual(m._movabs_immediate(self.data, secs, site),
                             value, name)
        self.assertEqual(m._movabs_immediate(self.data, secs, m.P1P2_SITE),
                         m.P1_TIMES_P2)
        self.assertEqual(m.P1_TIMES_P2, (m.P1 * m.P2) & m.MASK64)

    def test_fde_extent_and_body_hash(self):
        self.assertEqual(m.fde_extent(bytes(self.data), m.FUNCTION_START),
                         (m.FUNCTION_START, m.FUNCTION_END))
        self.assertEqual(self.checked['body_hash'], m.CENSUS_BODY)

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
