"""Controls for the node #115 RocksDB streaming XXH64 API."""
import random
import tempfile
from pathlib import Path
import unittest

from tools import xxh64_streaming115 as m


class XXH64StreamingTests(unittest.TestCase):
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

    def _stream(self, data, seed=0, splits=None):
        state = m.XXH64StreamingState.create()
        state.reset(seed)
        if splits is None:
            splits = (len(data),) if data else ()
        pos = 0
        for size in splits:
            self.assertEqual(state.update(data[pos:pos + size]), 0)
            pos += size
        self.assertEqual(pos, len(data))
        return state.digest()

    def test_xxh64_check_values(self):
        # Published XXH64 vectors anchor the model and the reference.
        self.assertEqual(self._stream(b'', 0), 0xEF46DB3751D8E999)
        self.assertEqual(self._stream(b'a', 0), 0xD24EC4F1A98C6E5B)
        self.assertEqual(self._stream(b'abc', 0), 0x44BC2CF5AD770999)
        self.assertEqual(m.xxh64_reference(b'', 0), 0xEF46DB3751D8E999)
        self.assertEqual(m.xxh64_reference(b'a', 0), 0xD24EC4F1A98C6E5B)
        self.assertEqual(m.xxh64_reference(b'abc', 0), 0x44BC2CF5AD770999)
        # Computed values both implementations agree on (and the
        # one-shot reconstruction in PR #5429 pins the same values).
        self.assertEqual(self._stream(b'123456789', 0), 0x8CB841DB40E6AE83)
        self.assertEqual(self._stream(bytes(range(32)), 0),
                         0xCBF59C5116FF32B4)
        self.assertEqual(self._stream(bytes(range(33)), 0, (16, 17)),
                         0x0C535D1ACAFB8EAD)
        self.assertEqual(self._stream(bytes(range(64)), 1,
                                      tuple([1] * 64)),
                         0x3CE5BDF7575926C0)
        self.assertEqual(self._stream(bytes(0xAB for _ in range(1024)), 0,
                                      (341, 341, 342)),
                         0x31C5118D25963EC5)
        self.assertEqual(self._stream(b'', 1), 0xD5AFBA1336A3BE4B)

    def test_create_reset_free_flow(self):
        state = m.XXH64StreamingState.create()
        # Uninitialised malloc memory: update/digest before reset is a
        # contract violation, not a modelled behaviour.
        with self.assertRaises(ValueError):
            state.update(b'abc')
        with self.assertRaises(ValueError):
            state.digest()
        self.assertEqual(state.reset(0), 0)
        self.assertEqual(state.total_len, 0)
        self.assertEqual(state.memsize, 0)
        self.assertEqual(state.v1, (0 + m.P1 + m.P2) & m.MASK64)
        self.assertEqual(state.v2, (0 + m.P2) & m.MASK64)
        self.assertEqual(state.v3, 0)
        self.assertEqual(state.v4, (-m.P1) & m.MASK64)
        self.assertEqual(state.free(), 0)
        # Use after freeState is not modelled.
        with self.assertRaises(ValueError):
            state.update(b'abc')
        with self.assertRaises(ValueError):
            state.free()

    def test_reset_seed_vector(self):
        for seed in (0, 1, 0x9E3779B185EBCA87, 0x0123456789ABCDEF):
            state = m.XXH64StreamingState.create()
            state.reset(seed)
            self.assertEqual(state.v1, (seed + m.P1 + m.P2) & m.MASK64)
            self.assertEqual(state.v2, (seed + m.P2) & m.MASK64)
            self.assertEqual(state.v3, seed & m.MASK64)
            self.assertEqual(state.v4, (seed - m.P1) & m.MASK64)
            # Reset is idempotent: a second reset restores the same state.
            state.update(b'hello world, this is longer than 32 bytes!')
            state.reset(seed)
            self.assertEqual(state.total_len, 0)
            self.assertEqual(state.memsize, 0)
            self.assertEqual(state.v3, seed & m.MASK64)

    def test_null_and_empty_update(self):
        state = m.XXH64StreamingState.create()
        state.reset(7)
        # Null data: returns 0, the state (including total_len) untouched.
        self.assertEqual(state.update(None), 0)
        self.assertEqual(state.total_len, 0)
        self.assertEqual(state.memsize, 0)
        # Empty input: also a no-op returning 0.
        self.assertEqual(state.update(b''), 0)
        self.assertEqual(state.total_len, 0)
        self.assertEqual(state.digest(), m.xxh64_reference(b'', 7))

    def test_state_layout_after_updates(self):
        state = m.XXH64StreamingState.create()
        state.reset(0)
        state.update(b'a' * 20)
        self.assertEqual(state.total_len, 20)
        self.assertEqual(state.memsize, 20)
        self.assertEqual(bytes(state.mem[:20]), b'a' * 20)
        # Crossing the 32-byte boundary processes one stripe.
        state.update(b'b' * 20)
        self.assertEqual(state.total_len, 40)
        self.assertEqual(state.memsize, 8)
        self.assertEqual(bytes(state.mem[:8]), b'b' * 8)
        # Exactly 32 more bytes: stripes processed, nothing buffered.
        state.update(b'c' * 32)
        self.assertEqual(state.total_len, 72)
        self.assertEqual(state.memsize, 8)
        # A single 64-byte feed from a fresh state: two stripes, empty mem.
        fresh = m.XXH64StreamingState.create()
        fresh.reset(0)
        fresh.update(bytes(range(64)))
        self.assertEqual(fresh.total_len, 64)
        self.assertEqual(fresh.memsize, 0)

    def test_chunking_invariance(self):
        rng = random.Random(20261109)
        for length in (0, 1, 31, 32, 33, 64, 65, 100, 1024):
            data = bytes(rng.randrange(256) for _ in range(length))
            for seed in (0, 1, 0x0123456789ABCDEF):
                want = m.xxh64_reference(data, seed)
                # Whole, halves, thirds, byte-by-byte, at-32 splits.
                chunkings = [(length,)] if length == 0 else [
                    (length,),
                    (length // 2, length - length // 2),
                    (length // 3, length // 3,
                     length - 2 * (length // 3)),
                    tuple([1] * length),
                    tuple(s for s in (32, 32, length - 64)
                          if s > 0) if length > 64 else (length,),
                ]
                for splits in chunkings:
                    self.assertEqual(self._stream(data, seed, splits), want)

    def test_model_matches_reference_on_all_cases(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), m.CASE_COUNT)
        rows = m.run_cases(cases)
        self.assertEqual(len(rows), m.CASE_COUNT)
        self.assertEqual(
            m.case_aggregate(rows),
            'cc1b2023dbe85386763c5ecb9b1979f27003d1a39270ba4251c0e335fb13531a')

    def test_prime_immediates(self):
        secs = m.unique_sections(self.data)
        for name, site, value in m.PRIME_SITES:
            self.assertEqual(m._movabs_immediate(self.data, secs, site),
                             value, f'{name} at {site:#x}')
        self.assertEqual(m.PRIME_SITES[0][2], (m.P1 + m.P2) & m.MASK64)
        self.assertEqual(m.PRIME_SITES[2][2], (-m.P1) & m.MASK64)

    def test_arm_call_sites(self):
        secs = m.unique_sections(self.data)
        for name, site, target in m.ARM_CALLS:
            self.assertEqual(m._call_target(self.data, secs, site), target,
                             f'{name} at {site:#x}')

    def test_fde_extents_and_body_hashes(self):
        for name, start, end, _cid, _sym, census_body in m.FUNCTIONS:
            with self.subTest(function=name):
                self.assertEqual(m.fde_extent(bytes(self.data), start),
                                 (start, end))
                self.assertEqual(self.checked['body_hashes'][name],
                                 census_body)

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
