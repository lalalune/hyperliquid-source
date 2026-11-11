"""Controls for the node #115 ComputeBuiltinChecksumWithLastByte multiply-xor arm."""
import hashlib
import json
import random
import tempfile
from pathlib import Path
import unittest

from tools import xxh3_last_byte115 as m


class Xxh3LastByteTests(unittest.TestCase):
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

    def test_public_xxh3_check_values(self):
        # Published XXH3_64bits sanity values anchor both implementations.
        self.assertEqual(m.xxh3_64_short(b''), 0x2D06800538D394C2)
        self.assertEqual(m.xxh3_64_short_reference(b''),
                         0x2D06800538D394C2)
        self.assertEqual(m.xxh3_64_short(b'a'), 0xE6C632B61E964E1F)
        self.assertEqual(m.xxh3_64_short_reference(b'a'),
                         0xE6C632B61E964E1F)
        self.assertEqual(m.xxh3_64_short(b'abc'), 0x78AF5F94892F3950)
        self.assertEqual(m.xxh3_64_short(b'abcd'), 0x6497A96F53A89890)
        self.assertEqual(m.xxh3_64_short(b'12345678'), 0x62E29B4CAD9E2EF6)
        self.assertEqual(m.xxh3_64_short(bytes(range(16))),
                         0x8355E3A6F61770DB)

    def test_empty_hash_is_the_folded_empty_branch(self):
        # XXH3_64_empty = avalanche_XXH64(secret[56..64) ^ secret[64..72)).
        words = m.secret_words(bytes(self.data),
                               m.unique_sections(self.data))
        self.assertEqual(
            m._avalanche64_full(words[7] ^ words[8]), m.EMPTY_HASH)

    def test_secret_words_match_rodata(self):
        words = m.secret_words(bytes(self.data),
                               m.unique_sections(self.data))
        self.assertEqual(tuple(words), m.SECRET_WORDS)
        self.assertEqual(words[3] ^ words[4], m.C1_9TO16)
        self.assertEqual(words[5] ^ words[6], m.C2_9TO16)
        self.assertEqual(words[1] ^ words[2], m.BITFLIP_4TO8)
        self.assertEqual((words[0] & m.MASK32) ^ (words[0] >> 32),
                         m.BITFLIP_1TO3)

    def test_model_rejects_long_inputs(self):
        with self.assertRaises(ValueError):
            m.xxh3_64_short(b'a' * 17)
        with self.assertRaises(ValueError):
            m.checksum_mulmix_arm(b'a' * 1024, 0)

    def test_arm_check_values(self):
        self.assertEqual(m.checksum_mulmix_arm(b'', 0), 0x38D394C2)
        self.assertEqual(m.checksum_mulmix_arm(b'', 0x61), 0xF91261FB)
        self.assertEqual(m.checksum_mulmix_arm(b'a', 0), 0x1E964E1F)
        self.assertEqual(m.checksum_mulmix_arm(b'abc', 0xFF), 0xADDC6C77)
        self.assertEqual(m.checksum_mulmix_arm(b'012345678', 0xAB),
                         0x42D3C624)
        self.assertEqual(m.checksum_mulmix_arm(bytes(range(16)), 0),
                         0xF61770DB)

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        self.assertTrue(all(len(payload) <= m.MAX_MODEL_LEN
                            for payload, _ in cases))
        rows = m.run_cases(cases)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            'e3a1ed59ddc08b455fb80269d75e9680f60439ca4eda4d69449d790a4e288bfe')

    def test_body_hashes(self):
        self.assertEqual(self.checked['body_hashes']['function'],
                         m.CENSUS_BODY['function'])
        self.assertEqual(self.checked['body_hashes']['helper'], m.HELPER_BODY)
        self.assertEqual(self.checked['body_hashes']['arm'], m.ARM_BODY)

    def test_records_hashes_match_windows(self):
        # Regression (from PR #5399): the packet generator once shadowed
        # the binary bytes with a case payload while writing records.json,
        # so the callee hashes came out as the empty-input SHA-256.
        # Records must use the verified body hashes, and they must agree
        # with windows.tsv.
        records = json.loads((m.PACKET / 'records.json').read_text())
        by_name = {r.get('name'): r for r in records['records']}
        windows = {}
        for line in (m.PACKET / 'windows.tsv').read_text().splitlines()[1:]:
            label, _, _, _, sha = line.split('\t')
            windows[label] = sha
        self.assertEqual(by_name['ROCKSDB_XXH3_64bits']['body_sha256'],
                         m.HELPER_BODY)
        self.assertEqual(by_name['ROCKSDB_XXH3_64bits']['body_sha256'],
                         windows['xxh3_helper'])
        arm = [r for r in records['records']
               if r.get('kind') == 'arm'][0]
        self.assertEqual(arm['body_sha256'], m.ARM_BODY)
        self.assertEqual(arm['body_sha256'], windows['mulmix_arm'])
        self.assertEqual(
            [r for r in records['records']
             if r.get('kind') == 'function'][0]['body_sha256'],
            m.CENSUS_BODY['function'])

    def test_all_immediates_appear_in_helper(self):
        for name in ('bitflip_1to3', 'empty_hash', 'bitflip_4to8',
                     'rrmxmx_mul', 'c1_9to16', 'c2_9to16', 'avalanche_mul',
                     'prime64_2', 'prime64_3'):
            self.assertTrue(self.checked['immediate_sites'][name], name)

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
