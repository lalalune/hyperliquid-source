"""Controls for the node #115 RocksDB CRC32C extend reconstruction."""
import hashlib
import tempfile
from pathlib import Path
import unittest

from tools import crc32c_extend115 as m


class Crc32cExtendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        cls.checked = m.verify(cls.data)
        cls.tables = cls.checked['tables']

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

    def test_tables_match_generated_polynomial(self):
        self.assertEqual(self.tables, m.generated_tables())

    def test_check_value_123456789(self):
        self.assertEqual(m.crc32c_extend(0, b'123456789', self.tables),
                         0xE3069283)
        self.assertEqual(m.crc32c_bitwise(0, b'123456789'), 0xE3069283)

    def test_empty_input_is_identity(self):
        for crc in (0, 1, 0xFFFFFFFF, 0x12345678):
            self.assertEqual(m.crc32c_extend(crc, b'', self.tables), crc)

    def test_model_matches_bitwise_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases, self.tables)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            'de9525c96f5014be9c0e97933f500f4d52a465d54a02bae7b17eeb93cefd0548')

    def test_windows_reject_corruption(self):
        for label, start, end in m.WINDOWS:
            with self.subTest(window=label):
                self.alter(start, end - start, m.verify)

    def test_tables_reject_corruption(self):
        for name, va in m.TABLES:
            with self.subTest(table=name):
                self.alter(va, 1024, m.verify)

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
