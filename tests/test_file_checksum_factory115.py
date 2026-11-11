"""Controls for the node #115 FileChecksumGenCrc32cFactory behaviour."""
import hashlib
import tempfile
from pathlib import Path
import unittest

from tools import file_checksum_factory115 as m


class FactoryTests(unittest.TestCase):
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

    def test_name_immediates_decode(self):
        # The movabs/cmpw immediates spell the expected name.
        self.assertEqual(m.WORD0.to_bytes(8, 'little'), b'FileChec')
        self.assertEqual(m.WORD1.to_bytes(8, 'little'), b'ksumCrc3')
        self.assertEqual(m.TAIL.to_bytes(2, 'little'), b'2c')
        self.assertEqual(m.EXPECTED_NAME, b'FileChecksumCrc32c')
        self.assertEqual(len(m.EXPECTED_NAME), 0x12)

    def test_create_check_values(self):
        self.assertTrue(m.create(b''))
        self.assertTrue(m.create(b'FileChecksumCrc32c'))
        self.assertFalse(m.create(b'FileChecksumCrc32'))
        self.assertFalse(m.create(b'FileChecksumCrc32cX'))
        self.assertFalse(m.create(b'FileChecksumCrc32c\x00'))
        self.assertFalse(m.create(b'filechecksumcrc32c'))
        self.assertFalse(m.create(b'FILECHECKSUMCRC32C'))
        self.assertFalse(m.create(b'FileChecksumCrc32d'))
        self.assertFalse(m.create(b'FileChecksumCrc32cc'))
        for n in range(1, 18):
            self.assertFalse(m.create(b'FileChecksumCrc32c'[:n]),
                             f'prefix of length {n} must be rejected')
        # One wrong byte at each position is rejected.
        for pos in range(18):
            mutated = bytearray(b'FileChecksumCrc32c')
            mutated[pos] ^= 0x01
            self.assertFalse(m.create(bytes(mutated)), f'pos {pos}')

    def test_init_layout(self):
        init = m.init_object()
        self.assertEqual(init['vptr'], 0x64D7970)
        self.assertEqual(init['crc_u32_at_0x8'], 0)
        self.assertEqual(init['checksum_string_ptr'], 'object+0x20')
        self.assertEqual(init['checksum_string_len_at_0x18'], 0)
        self.assertEqual(init['checksum_string_first_byte_at_0x20'], 0)
        self.assertEqual(init['object_size'], 0x30)

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            '1db2e4799448982319ca4406ff0ad66fa4c041f91587938ba6191500d6e971f2')
        created = sum(1 for _, c in rows if c)
        self.assertEqual(created, 160)

    def test_body_hash_matches_census(self):
        self.assertEqual(self.checked['body_hash'],
                         m.CENSUS_BODY['function'])
        self.assertEqual(self.checked['body_hash'],
                         '469590278ff13b8ed347c4085fc75e93a54c8c18fecbbff38b086c2f92fc22cb')

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
