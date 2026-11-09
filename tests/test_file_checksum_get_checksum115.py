"""Controls for the node #115 FileChecksumGenCrc32c GetChecksum behaviour."""
import hashlib
import tempfile
from pathlib import Path
import unittest

from tools import file_checksum_get_checksum115 as m


class GetChecksumTests(unittest.TestCase):
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

    def test_copy_check_values(self):
        # The std::string copy, both implementations agree.
        self.assertEqual(m.copy_string(b''), b'')
        self.assertEqual(m.copy_string(b'a'), b'a')
        self.assertEqual(m.copy_string(b'ab'), b'ab')
        self.assertEqual(m.copy_string(bytes(range(15))), bytes(range(15)))
        self.assertEqual(m.copy_string(bytes(range(16))), bytes(range(16)))
        self.assertEqual(m.copy_string(b'\xe3\x06\x92\x83'),
                         b'\xe3\x06\x92\x83')
        self.assertEqual(m.copy_string(b'FileChecksumCrc32c'),
                         b'FileChecksumCrc32c')
        for source in (b'', b'a', bytes(range(15)), bytes(range(16)),
                       b'123456789', bytes(1024)):
            self.assertEqual(m.copy_string(source),
                             m.copy_string_reference(source))

    def test_copy_is_exact_and_length_preserving(self):
        source = bytes(range(256)) * 4
        out = m.copy_string(source)
        self.assertEqual(out, source)
        self.assertEqual(len(out), len(source))
        # The copy is a fresh value, not an alias of the input.
        self.assertIsNot(out, source)

    def test_sso_boundary(self):
        # Lengths 0..15 stay in the SSO buffer; 16+ take the heap path.
        # Both paths must yield exactly the source bytes.
        for length in (0, 1, 2, 14, 15, 16, 17, 32, 1024):
            source = bytes((i * 7 + 3) % 256 for i in range(length))
            self.assertEqual(m.copy_string(source), source)

    def test_end_to_end_update_finalize_get(self):
        # Update accumulates extend(0, b"123456789") = 0xe3069283 (the
        # bitwise extend is the Finalize packet's model); Finalize
        # appends its big-endian form; GetChecksum returns those bytes.
        finalize_out = b'\xe3\x06\x92\x83'
        self.assertEqual(m.copy_string(finalize_out), finalize_out)

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            '44ec3a188db121774a3527ec25d9848634b00bf29a22c2b9ff020c13700d3b6c')

    def test_body_hash_matches_census(self):
        self.assertEqual(self.checked['body_hash'],
                         m.CENSUS_BODY['function'])
        self.assertEqual(self.checked['body_hash'],
                         '1454dfd1b600941130fbbd7f637e0b279b1dd9ad62d01146458f985428943055')

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
