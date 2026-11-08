"""Controls for the node #115 RocksDB CRC32C combine reconstruction."""
import hashlib
import random
import tempfile
from pathlib import Path
import unittest

from tools import crc32c_combine115 as m


class Crc32cCombineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        cls.checked = m.verify(cls.data)
        cls.table = cls.checked['table']

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

    def test_table_structure(self):
        factors = m.table_factors(self.table)
        self.assertEqual(factors[0], m.advance(1, 4))
        for i in range(61):
            self.assertEqual(m.mul_poly(factors[i], factors[i]),
                             factors[i + 1])
        self.assertEqual(self.table[62], 0)
        self.assertEqual(self.table[63], 0)

    def test_check_values(self):
        self.assertEqual(m.crc32c_combine(0, 0, 0, self.table), 0)
        for crc1, crc2 in ((0, 0), (1, 2), (0xFFFFFFFF, 0x12345678)):
            self.assertEqual(m.crc32c_combine(crc1, crc2, 0, self.table),
                             crc1 ^ crc2)
        self.assertEqual(
            m.crc32c_combine(0xFFFFFFFF, 0, 9, self.table), 0x441A975C)

    def test_split_concatenation(self):
        # Stored-form concatenation needs the extra advance(0xFFFFFFFF, n)
        # term; a bare ~combine(~s1, ~s2, n) is not the stored CRC.
        rng = random.Random(20261109)
        for _ in range(50):
            n1 = rng.randrange(0, 32)
            n2 = rng.randrange(0, 32)
            x = bytes(rng.randrange(256) for _ in range(n1))
            y = bytes(rng.randrange(256) for _ in range(n2))
            s1 = m.extend_stored_bitwise(0, x)
            s2 = m.extend_stored_bitwise(0, y)
            combined = m.crc32c_combine(~s1 & 0xFFFFFFFF,
                                        ~s2 & 0xFFFFFFFF, n2, self.table)
            self.assertEqual(
                ((~combined) & 0xFFFFFFFF) ^ m.advance(0xFFFFFFFF, n2),
                m.extend_stored_bitwise(0, x + y))
            # Raw-state reading: crc1 = raw state after X, crc2 = raw CRC
            # of Y from a zero initial state; the result is the raw state
            # after X || Y.
            raw_x = (~s1) & 0xFFFFFFFF
            raw_y_from_zero = (~m.extend_stored_bitwise(0xFFFFFFFF, y)) & 0xFFFFFFFF
            self.assertEqual(
                m.crc32c_combine(raw_x, raw_y_from_zero, n2, self.table),
                (~m.extend_stored_bitwise(0, x + y)) & 0xFFFFFFFF)

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases, self.table)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            '43ed075c833d623632c64bc6395fc49097144f05a621e3747312f9bfcef2fe0e')

    def test_windows_reject_corruption(self):
        for label, start, end in m.WINDOWS:
            with self.subTest(window=label):
                self.alter(start, end - start, m.verify)

    def test_tables_reject_corruption(self):
        for name, va, size in m.TABLES:
            with self.subTest(table=name):
                self.alter(va, size, m.verify)

    def test_regenerated_packet_matches_committed(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'packet'
            m.generate(bytes(self.data), dest)
            for name in ('tables.tsv', 'windows.tsv', 'cases.tsv',
                         'result.json', 'records.json'):
                committed = (m.PACKET / name).read_bytes()
                fresh = (dest / name).read_bytes()
                self.assertEqual(fresh, committed, name)


if __name__ == '__main__':
    unittest.main()
