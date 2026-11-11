"""Controls for the node #115 ComputeBuiltinChecksumWithLastByte xxhash64 arm."""
import hashlib
import random
import tempfile
from pathlib import Path
import unittest

from tools import xxh64_last_byte115 as m


class Xxh64LastByteTests(unittest.TestCase):
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

    def test_xxh64_check_vectors(self):
        # Public XXH64 vectors anchor both implementations.
        self.assertEqual(m.xxh64_oneshot(b'', 0), 0xEF46DB3751D8E999)
        self.assertEqual(m.XXH64State(0).digest(), 0xEF46DB3751D8E999)
        self.assertEqual(m.xxh64_oneshot(b'a', 0), 0xD24EC4F1A98C6E5B)
        state = m.XXH64State(0)
        state.update(b'a')
        self.assertEqual(state.digest(), 0xD24EC4F1A98C6E5B)
        self.assertEqual(m.xxh64_oneshot(b'', 0),
                         m.XXH64State(0).digest())

    def test_reset_accumulators(self):
        # Seed 0 initialises v1..v4 exactly as the binary's reset does.
        state = m.XXH64State(0)
        self.assertEqual(state.v1, 0x60EA27EEADC0B5D6)
        self.assertEqual(state.v2, 0xC2B2AE3D27D4EB4F)
        self.assertEqual(state.v3, 0)
        self.assertEqual(state.v4, 0x61C8864E7A143579)
        self.assertEqual(state.total_len, 0)
        self.assertEqual(state.memsize, 0)

    def test_streaming_matches_oneshot_across_boundaries(self):
        # Split updates (as the arm does: data, then one last byte) must
        # equal the one-shot hash of the concatenation, including across
        # the 32-byte stripe boundary.
        rng = random.Random(7)
        for length in (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33,
                       63, 64, 65, 127, 128, 256, 1024):
            data = bytes(rng.randrange(256) for _ in range(length))
            last = rng.randrange(256)
            state = m.XXH64State(0)
            state.update(data)
            state.update(bytes((last,)))
            self.assertEqual(state.digest(),
                             m.xxh64_oneshot(data + bytes((last,)), 0),
                             f'length {length}')
            # A single update of the concatenation must agree too.
            state2 = m.XXH64State(0)
            state2.update(data + bytes((last,)))
            self.assertEqual(state2.digest(), state.digest(),
                             f'length {length} single update')

    def test_arm_check_values(self):
        self.assertEqual(m.checksum_xxh64_arm(b'', 0), 0xDB052768)
        self.assertEqual(m.checksum_xxh64_arm(b'123456789', 0), 0x1B63A378)
        self.assertEqual(m.checksum_xxh64_arm(b'', 0x61), 0xA98C6E5B)
        long_data = bytes(0xAB for _ in range(1024))
        self.assertEqual(m.checksum_xxh64_arm(long_data, 0xFF), 0xBB863C8A)
        # The arm is the low 32 bits of the 64-bit digest.
        self.assertEqual(
            m.checksum_xxh64_arm(b'123456789', 0),
            m.xxh64_oneshot(b'123456789\x00', 0) & 0xFFFFFFFF)

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            '22465ac218d06f22bb15f4157a7fe922bf27dd22dd6f70755b965a6e9a71985a')

    def test_callee_body_hashes_match_census(self):
        for key, expect in m.CENSUS_BODY.items():
            self.assertEqual(self.checked['body_hashes'][key], expect, key)
        self.assertEqual(self.checked['body_hashes']['create'], m.CREATE_BODY)
        self.assertEqual(self.checked['body_hashes']['free'], m.FREE_BODY)

    def test_records_callee_hashes_match_windows(self):
        # Regression: the packet generator once shadowed the binary bytes
        # with a case payload while writing records.json, so the
        # createState/freeState hashes came out as the empty-input SHA-256.
        import json
        records = json.loads((m.PACKET / 'records.json').read_text())
        by_name = {r.get('name'): r for r in records['records']}
        windows = {}
        for line in (m.PACKET / 'windows.tsv').read_text().splitlines()[1:]:
            label, _, _, _, sha = line.split('\t')
            windows[label] = sha
        self.assertEqual(by_name['XXH64_createState']['body_sha256'],
                         m.CREATE_BODY)
        self.assertEqual(by_name['XXH64_freeState']['body_sha256'],
                         m.FREE_BODY)
        self.assertEqual(by_name['XXH64_createState']['body_sha256'],
                         windows['xxh64_create'])
        self.assertEqual(by_name['XXH64_freeState']['body_sha256'],
                         windows['xxh64_free'])

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
