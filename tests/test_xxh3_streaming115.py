"""Tests for tools/xxh3_streaming115.py.

The two published anchors are XXH3_64bits(b"", 0) = 0x2d06800538d394c2
and XXH3_64bits(b"a", 0) = 0xe6c632b61e964e1f, checked through the
streaming API (createState + reset + digest, no updates). Every other
assertion compares the streaming transliteration against the
independent one-shot reference, or checks a pinned binary fact (body
hashes, reset primes, state offsets, the AVX2 replay).
"""

import hashlib
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import xxh3_streaming115 as m

EMPTY = 0x2D06800538D394C2
A = 0xE6C632B61E964E1F


def _stream(data, chunks=None):
    st = m.XXH3State()
    st.reset()
    if chunks is None:
        chunks = [data]
    for ch in chunks:
        st.update(ch)
    return st.digest()


class AnchorTests(unittest.TestCase):
    def test_published_empty(self):
        self.assertEqual(_stream(b""), EMPTY)

    def test_published_a(self):
        self.assertEqual(_stream(b"a"), A)

    def test_empty_with_updates(self):
        st = m.XXH3State()
        st.reset()
        st.update(b"")
        st.update(None)
        self.assertEqual(st.digest(), EMPTY)


class LifecycleTests(unittest.TestCase):
    def test_create_state_alignment(self):
        for ptr in (0x1000, 0x1001, 0x103F, 0x1040, 0x12345678):
            aligned, delta = m.create_state_align(ptr)
            self.assertEqual(aligned % 64, 0)
            self.assertTrue(1 <= delta <= 64)
            self.assertEqual(aligned, ptr + delta)
            self.assertEqual(m.free_state_base(aligned, delta), ptr)

    def test_reset_primes(self):
        st = m.XXH3State()
        st.reset()
        self.assertEqual(st.acc, list(m.ACC_INIT))
        self.assertEqual(st.total_len, 0)
        self.assertEqual(st.buffered_size, 0)
        self.assertEqual(st.nb_stripes_so_far, 0)
        self.assertEqual(st.nb_stripes_per_block, 16)
        self.assertEqual(st.secret_limit, 128)
        self.assertEqual(st.seed, 0)
        self.assertEqual(st.use_seed, 0)
        self.assertEqual(st.custom_secret, m.KSECRET)

    def test_null_update_is_noop(self):
        st = m.XXH3State()
        st.reset()
        st.update(b"abc")
        before = (list(st.acc), bytes(st.buffer), st.buffered_size,
                  st.total_len, st.nb_stripes_so_far)
        self.assertEqual(st.update(None), 0)
        after = (list(st.acc), bytes(st.buffer), st.buffered_size,
                 st.total_len, st.nb_stripes_so_far)
        self.assertEqual(before, after)

    def test_binary_authenticates(self):
        blob = m.BINARY.read_bytes()
        self.assertEqual(m.verify_binary(blob), [])
        self.assertEqual(hashlib.sha256(blob).hexdigest(), m.ARTIFACT_DIGEST)


class DigestTests(unittest.TestCase):
    def test_chunking_invariance(self):
        rng = random.Random(11)
        for n in (17, 100, 240, 241, 300, 1025, 2048, 5000):
            data = bytes(rng.randrange(256) for _ in range(n))
            want = m.ref_oneshot(data)
            self.assertEqual(_stream(data), want)
            self.assertEqual(
                _stream(data, [data[i:i + 1] for i in range(n)]) if n <= 300
                else _stream(data, [data[:100], data[100:]]), want)
            self.assertEqual(
                _stream(data, [data[i:i + 64] for i in range(0, n, 64)]),
                want)

    def test_buffered_size_after_update(self):
        st = m.XXH3State()
        st.reset()
        st.update(bytes(300))
        self.assertEqual(st.buffered_size, 44)
        self.assertEqual(st.nb_stripes_so_far, 4)
        st2 = m.XXH3State()
        st2.reset()
        st2.update(bytes(256))
        self.assertEqual(st2.buffered_size, 256)

    def test_seeded_short_digest(self):
        rng = random.Random(3)
        for n in (0, 1, 5, 16, 100, 240):
            data = bytes(rng.randrange(256) for _ in range(n))
            seed = rng.randrange(1 << 64)
            st = m.XXH3State()
            st.reset()
            st.use_seed = 1
            st.seed = seed
            st.update(data)
            self.assertEqual(st.digest(), m.ref_oneshot(data, m.KSECRET, seed))

    def test_secret_windows_matter(self):
        # A 2-byte input reads only secret[0..8) on the short path.
        base = m.ref_oneshot(b"ab", m.KSECRET, 0)
        mutated = bytearray(m.KSECRET)
        mutated[0] ^= 0x01
        self.assertNotEqual(m.ref_oneshot(b"ab", bytes(mutated), 0), base)
        mutated = bytearray(m.KSECRET)
        mutated[100] ^= 0x01
        self.assertEqual(m.ref_oneshot(b"ab", bytes(mutated), 0), base)

    def test_avx2_replay_matches_scalar(self):
        rng = random.Random(7)
        for _ in range(50):
            stripe = bytes(rng.randrange(256) for _ in range(64))
            secret = bytes(rng.randrange(256) for _ in range(64))
            acc = [rng.randrange(1 << 64) for _ in range(8)]
            self.assertEqual(m._accumulate_512(acc, stripe, secret),
                             m._accumulate_512_avx2(acc, stripe, secret))

    def test_long_inputs_match_oneshot(self):
        rng = random.Random(23)
        for n in (241, 1000, 1024, 4096, 5000):
            data = bytes(rng.randrange(256) for _ in range(n))
            self.assertEqual(_stream(data), m.ref_oneshot(data))


if __name__ == "__main__":
    unittest.main()
