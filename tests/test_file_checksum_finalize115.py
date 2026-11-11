"""Controls for the node #115 FileChecksumGenCrc32c Finalize behaviour."""
import hashlib
import tempfile
from pathlib import Path
import unittest

from tools import file_checksum_finalize115 as m


class FinalizeTests(unittest.TestCase):
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

    def test_be32_check_values(self):
        # Big-endian encoding, both implementations agree.
        self.assertEqual(m.be32_pack(0xE3069283), b'\xe3\x06\x92\x83')
        self.assertEqual(m.be32_bswap(0xE3069283), b'\xe3\x06\x92\x83')
        self.assertEqual(m.be32_pack(0), b'\x00\x00\x00\x00')
        self.assertEqual(m.be32_bswap(0xA282EAD8), b'\xa2\x82\xea\xd8')
        self.assertEqual(m.be32_pack(0x12345678), b'\x12\x34\x56\x78')
        for crc in (0, 1, 0xE3069283, 0xA282EAD8, 0xFFFFFFFF, 0x12345678):
            self.assertEqual(m.be32_pack(crc), m.be32_bswap(crc))

    def test_finalize_check_values(self):
        self.assertEqual(m.finalize(0xE3069283, b''), b'\xe3\x06\x92\x83')
        self.assertEqual(m.finalize(0, b'abc'), b'abc\x00\x00\x00\x00')
        self.assertEqual(m.finalize(0xA282EAD8, b''), b'\xa2\x82\xea\xd8')
        self.assertEqual(m.finalize(0x12345678, b'prefix'),
                         b'prefix\x12\x34\x56\x78')
        # End to end: Update accumulates extend(0, b"123456789").
        self.assertEqual(
            m.finalize(m.extend_bitwise(0, b'123456789'), b''),
            b'\xe3\x06\x92\x83')

    def test_finalize_preserves_prior_and_appends_four(self):
        prior = bytes(range(32))
        out = m.finalize(0xDEADBEEF, prior)
        self.assertEqual(out[:32], prior)
        self.assertEqual(out[32:], b'\xde\xad\xbe\xef')
        self.assertEqual(len(out), len(prior) + 4)

    def test_guard_boundary(self):
        # The binary throws when (max_size - len) <= 3, i.e. the append
        # runs exactly when len <= max_size - 4. A max_size-3 prior
        # cannot be materialised, so the boundary is pinned through the
        # guard predicate the binary computes.
        self.assertTrue(m.guard_allows(m.MAX_SIZE - 4))
        self.assertFalse(m.guard_allows(m.MAX_SIZE - 3))
        self.assertFalse(m.guard_allows(m.MAX_SIZE))
        self.assertTrue(m.guard_allows(0))
        self.assertTrue(m.guard_allows(1024))
        self.assertEqual(m.finalize_reference(0x12345678, b''),
                         b'\x12\x34\x56\x78')

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            '29d1743475f724c1ddafe6ff4a03cf0af2525b888d9789c0ce5884e0c3626d2f')

    def test_body_hash_matches_census(self):
        self.assertEqual(self.checked['body_hash'],
                         m.CENSUS_BODY['function'])
        self.assertEqual(self.checked['body_hash'],
                         'd3e24d9354044c97cd94d122250a157da9131c7ccd36d49330e912d3fd1c7007')

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
