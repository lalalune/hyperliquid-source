"""Controls for the node #115 ComputeBuiltinChecksum dispatcher."""
import hashlib
import random
import tempfile
from pathlib import Path
import unittest

from tools import checksum115 as m


class ChecksumTests(unittest.TestCase):
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
        # The binary expresses the same Mask as ror32 minus 0x5d7d1528.
        for crc in (0, 1, 0xE3069283, 0xFFFFFFFF, 0x12345678):
            self.assertEqual(m.mask(crc), m.mask_via_sub(crc))

    def test_xxh32_check_values(self):
        self.assertEqual(m.xxh32_oneshot(b'', 0), 0x02CC5D05)
        self.assertEqual(m.xxh32_oneshot(b'a', 0), 0x550D7456)
        self.assertEqual(m.xxh32_oneshot(b'abc', 0), 0x32D153FF)

    def test_xxh64_check_values(self):
        self.assertEqual(m.xxh64_oneshot(b'', 0) & 0xFFFFFFFF, 0x51D8E999)
        self.assertEqual(m.xxh64_oneshot(b'a', 0) & 0xFFFFFFFF, 0xA98C6E5B)

    def test_xxh3_check_values(self):
        self.assertEqual(m.xxh3_64_short(b''), 0x2D06800538D394C2)
        self.assertEqual(m.xxh3_64_short(b'a'), 0xE6C632B61E964E1F)

    def test_dispatch_check_values(self):
        self.assertEqual(m.compute_checksum(1, b'123456789'), 0xC78AB0E5)
        self.assertEqual(m.compute_checksum(1, b''), 0xA282EAD8)
        self.assertEqual(m.compute_checksum(2, b'a'), 0x550D7456)
        self.assertEqual(m.compute_checksum(3, b''), 0x51D8E999)
        self.assertEqual(m.compute_checksum(3, b'a'), 0xA98C6E5B)
        self.assertEqual(m.compute_checksum(4, b''), 0)
        # Type 4, n == 1: (u32) XXH3_64bits(b"") ^ (0x61 * 0x6b9083d9).
        self.assertEqual(m.compute_checksum(4, b'a'),
                         (0x38D394C2 ^ (0x61 * 0x6B9083D9 & 0xFFFFFFFF))
                         & 0xFFFFFFFF)
        self.assertEqual(m.compute_checksum(4, b'abc'), 0xBC378FB7)
        self.assertEqual(m.compute_checksum(0, b'abc'), 0)
        self.assertEqual(m.compute_checksum(5, b'abc'), 0)
        self.assertEqual(m.compute_checksum(7, b'abc'), 0)

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases, self.table)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            '60328b51e92acd9aca52afea99709d090534f8109ec172dd371d2dd066fd9647')

    def test_mask_sub_site_in_text(self):
        secs = m.unique_sections(self.data)
        self.assertIn(m.MASK_SUB_SITE,
                      m.mask_sub_sites(self.data, secs))

    def test_callee_body_hashes(self):
        self.assertEqual(self.checked['callee_hashes']['xxh32'], m.XXH32_BODY)
        self.assertEqual(self.checked['callee_hashes']['xxh64'], m.XXH64_BODY)
        self.assertEqual(self.checked['callee_hashes']['xxh3'], m.XXH3_BODY)
        self.assertEqual(self.checked['body_hash'],
                         m.CENSUS_BODY['function'])

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
