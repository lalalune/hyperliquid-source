"""Controls for the node #115 ComputeBuiltinChecksumWithLastByte CRC32C arm."""
import hashlib
import random
import tempfile
from pathlib import Path
import unittest

from tools import checksum_last_byte115 as m


class ChecksumLastByteTests(unittest.TestCase):
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

    def test_extend_check_values(self):
        # Known CRC32C vectors anchor both extend implementations.
        self.assertEqual(m.extend_bitwise(0, b'123456789'), 0xE3069283)
        self.assertEqual(m.extend_table(0, b'123456789', self.table),
                         0xE3069283)
        self.assertEqual(m.extend_bitwise(0, b'a'), 0xC1D04330)
        self.assertEqual(m.extend_table(0, b'a', self.table), 0xC1D04330)
        self.assertEqual(m.extend_bitwise(0, b'\x00'), 0x527D5351)
        self.assertEqual(m.extend_bitwise(0, b''), 0)
        self.assertEqual(m.extend_bitwise(0x12345678, b''), 0x12345678)

    def test_mask(self):
        self.assertEqual(m.mask(0), 0xA282EAD8)
        self.assertEqual(m.mask(0xFFFFFFFF), 0xA282EAD7)
        # ror32(1, 15) = 1 << 17, plus the constant.
        self.assertEqual(m.mask(1), (0x20000 + 0xA282EAD8) & 0xFFFFFFFF)

    def test_check_values(self):
        self.assertEqual(m.checksum_crc32c_arm(b'', 0), 0x49258FD2)
        self.assertEqual(m.checksum_crc32c_arm(b'123456789', 0), 0xDD227149)
        self.assertEqual(m.checksum_crc32c_arm(b'', 0x61), 0x28E46E78)
        long_data = bytes(0xAB for _ in range(1024))
        self.assertEqual(m.checksum_crc32c_arm(long_data, 0xFF), 0x2A29E790)

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases, self.table)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            '662c61f4dbb92f43954a850644475a2d9a300c93e71ba28750577166904a3736')

    def test_mask_constant_is_unique_in_text(self):
        secs = m.unique_sections(self.data)
        self.assertEqual(m.mask_constant_sites(self.data, secs),
                         [m.MASK_IMMEDIATE_ADDR])

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
