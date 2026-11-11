"""Controls for the node #115 ComputeBuiltinChecksumWithLastByte xxhash arm."""
import hashlib
import json
import random
import tempfile
from pathlib import Path
import unittest

from tools import xxh32_last_byte115 as m


class Xxh32LastByteTests(unittest.TestCase):
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

    def test_public_xxh32_check_vectors(self):
        # Public XXH32 vectors anchor the reference implementation.
        # (Correction: an earlier revision wrongly added XXH64-style
        # merge rounds to the "public" reference and claimed a
        # deviation; per the upstream xxHash spec v0.2.0, XXH32
        # convergence is the rotate-sum only, so the 16-byte value
        # below is the standard one.)
        self.assertEqual(m.xxh32_oneshot(b'', 0), 0x02CC5D05)
        self.assertEqual(m.xxh32_oneshot(b'a', 0), 0x550D7456)
        self.assertEqual(m.xxh32_oneshot(b'abc', 0), 0x32D153FF)
        self.assertEqual(m.xxh32_oneshot(b'abcd', 0), 0xA3643705)
        self.assertEqual(m.xxh32_oneshot(b'0123456789abcdef', 0), 0xC2C45B69)
        state = m.XXH32State(0)
        state.update(b'0123456789abcdef')
        self.assertEqual(state.digest(), 0xC2C45B69)

    def test_reset_accumulators(self):
        # Seed 0 initialises v1..v4 exactly as the binary's reset does
        # (seed vector [P1+P2, P2, 0, -P1] at 0x451ae0).
        state = m.XXH32State(0)
        self.assertEqual(state.v1, 0x24234428)
        self.assertEqual(state.v2, 0x85EBCA77)
        self.assertEqual(state.v3, 0)
        self.assertEqual(state.v4, 0x61C8864F)
        self.assertEqual(state.total_len, 0)
        self.assertEqual(state.memsize, 0)
        self.assertFalse(state.large_len)

    def test_large_len_flag(self):
        state = m.XXH32State(0)
        state.update(b'a' * 15)
        self.assertFalse(state.large_len)
        state.update(b'a')
        self.assertTrue(state.large_len)

    def test_streaming_matches_oneshot_across_boundaries(self):
        # Split updates (as the arm does: data, then one last byte) must
        # equal the one-shot hash of the concatenation, including across
        # the 16-byte stripe boundary.
        rng = random.Random(7)
        for length in (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33,
                       63, 64, 65, 127, 128, 256, 1024):
            data = bytes(rng.randrange(256) for _ in range(length))
            last = rng.randrange(256)
            state = m.XXH32State(0)
            state.update(data)
            state.update(bytes((last,)))
            self.assertEqual(state.digest(),
                             m.xxh32_oneshot(data + bytes((last,)), 0),
                             f'length {length}')
            # A single update of the concatenation must agree too.
            state2 = m.XXH32State(0)
            state2.update(data + bytes((last,)))
            self.assertEqual(state2.digest(), state.digest(),
                             f'length {length} single update')

    def test_arm_check_values(self):
        self.assertEqual(m.checksum_xxh32_arm(b'', 0), 0xCF65B03E)
        self.assertEqual(m.checksum_xxh32_arm(b'123456789', 0), 0x08FAF2DA)
        # Short input: the arm agrees with the public XXH32("a") vector.
        self.assertEqual(m.checksum_xxh32_arm(b'', 0x61), 0x550D7456)
        self.assertEqual(m.checksum_xxh32_arm(b'0123456789abcdef', 0),
                         0xB9EB4E9B)
        long_data = bytes(0xAB for _ in range(1024))
        self.assertEqual(m.checksum_xxh32_arm(long_data, 0xFF), 0x8AB0E4DD)

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            'ed7bf572431d2a8591e7c587b9064acdf2833f2b9532d33da13106c2746afc5d')

    def test_callee_body_hashes(self):
        self.assertEqual(self.checked['body_hashes']['function'],
                         m.CENSUS_BODY['function'])
        self.assertEqual(self.checked['body_hashes']['create'], m.CREATE_BODY)
        self.assertEqual(self.checked['body_hashes']['free'], m.FREE_BODY)
        self.assertEqual(self.checked['body_hashes']['reset'], m.RESET_BODY)
        self.assertEqual(self.checked['body_hashes']['update'], m.UPDATE_BODY)
        self.assertEqual(self.checked['body_hashes']['digest'], m.DIGEST_BODY)

    def test_records_callee_hashes_match_windows(self):
        # Regression (from PR #5399): the packet generator once shadowed
        # the binary bytes with a case payload while writing records.json,
        # so the createState/freeState hashes came out as the empty-input
        # SHA-256. Records must use the verified body hashes, and they
        # must agree with windows.tsv.
        records = json.loads((m.PACKET / 'records.json').read_text())
        by_name = {r.get('name'): r for r in records['records']}
        windows = {}
        for line in (m.PACKET / 'windows.tsv').read_text().splitlines()[1:]:
            label, _, _, _, sha = line.split('\t')
            windows[label] = sha
        for name, body, window in (
                ('XXH32_createState', m.CREATE_BODY, 'xxh32_create'),
                ('XXH32_freeState', m.FREE_BODY, 'xxh32_free'),
                ('ROCKSDB_XXH32_reset', m.RESET_BODY, 'xxh32_reset'),
                ('ROCKSDB_XXH32_update', m.UPDATE_BODY, 'xxh32_update'),
                ('ROCKSDB_XXH32_digest', m.DIGEST_BODY, 'xxh32_digest')):
            self.assertEqual(by_name[name]['body_sha256'], body, name)
            self.assertEqual(by_name[name]['body_sha256'], windows[window],
                             name)

    def test_all_primes_appear_in_update_and_digest(self):
        for name in m.PRIMES:
            self.assertTrue(self.checked['prime_sites'][name], name)

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
