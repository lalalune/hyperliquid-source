"""Tests for tools/xxh3_hashlong_128b115.py.

Every assertion compares the disassembly transliteration against the
independent loop-form reference, or checks a pinned binary fact (body
hash, immediates, secret table, callers). The check values are computed
values confirmed against the system libxxhash 0.8.2 oracle at the
128-bit entry points during development.
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import xxh3_hashlong_128b115 as m


class HashLong128bTests(unittest.TestCase):
    def test_check_values(self):
        # Computed values, confirmed against the system libxxhash 0.8.2
        # oracle at the 128-bit entry points during development
        # (native execution of the extracted bytes: 120 cases across
        # both entry points, 0 mismatches; oracle: 600/600).
        low, high = m.hashlong_128b_default(bytes(241))
        self.assertEqual((low, high),
                         (0x5C5B5D5D40C59CE3, 0xB9B45065A364C5B9))
        low, high = m.hashlong_128b_default(b"a" * 241)
        self.assertEqual((low, high),
                         (0xF6CFEF5C5ACA1930, 0x3E7BEBE4A2C07B0B))
        low, high = m.hashlong_128b_default(
            bytes((j * 7 + 3) & 0xFF for j in range(512)))
        self.assertEqual((low, high),
                         (0xF58202B8D9019D1D, 0x1AF3D0367BA5A0C4))
        low, high = m.hashlong_128b_with_seed(
            bytes(j & 0xFF for j in range(1024)), m.PRIME64_1)
        self.assertEqual((low, high),
                         (0xC09766CEA347AAE6, 0xA8668790BF9BC795))
        low, high = m.hashlong_128b_with_seed(bytes(241), 1)
        self.assertEqual((low, high),
                         (0x8EF42DD2D1D7A75F, 0x9BEC9240A8A55CE9))
        low, high = m.hashlong_128b_with_seed(
            bytes(j & 0xFF for j in range(2048)), 7)
        self.assertEqual((low, high),
                         (0x607B46EF2832250A, 0xD2D295287DAD8C9D))
        low, high = m.hashlong_128b_with_seed(
            bytes((j * 13 + 5) & 0xFF for j in range(300)), 0xDEADBEEF)
        self.assertEqual((low, high),
                         (0xB33F489CD50CCE5B, 0x3BFF3DB7C6F0710B))

    def test_len_out_of_scope(self):
        with self.assertRaises(ValueError):
            m.hashlong_128b_default(bytes(240))
        with self.assertRaises(ValueError):
            m.hashlong_128b_with_seed(bytes(128), 0)
        with self.assertRaises(ValueError):
            m.hashlong_128b_with_seed(bytes(0), 5)

    def test_agrees_with_reference(self):
        import random
        rng = random.Random(11)
        for length in (241, 242, 256, 300, 512, 1024, 1025, 2048, 4096):
            for _ in range(4):
                data = bytes(rng.randrange(256) for _ in range(length))
                seed = rng.getrandbits(64)
                self.assertEqual(m.hashlong_128b_with_seed(data, seed),
                                 m.ref_hashlong_128b_with_seed(data, seed))
                self.assertEqual(m.hashlong_128b_default(data),
                                 m.ref_hashlong_128b_default(data))

    def test_boundary_lengths(self):
        import random
        rng = random.Random(13)
        for length in (241, 242, 255, 256, 257, 320, 321, 1023, 1024,
                       1025, 1087, 1088, 1089, 2048, 2049):
            data = bytes(rng.randrange(256) for _ in range(length))
            seed = rng.getrandbits(64)
            self.assertEqual(m.hashlong_128b_with_seed(data, seed),
                             m.ref_hashlong_128b_with_seed(data, seed))
            self.assertEqual(m.hashlong_128b_default(data),
                             m.ref_hashlong_128b_default(data))

    def test_seed_changes_output(self):
        data = bytes(range(241))
        self.assertNotEqual(m.hashlong_128b_with_seed(data, 0),
                            m.hashlong_128b_with_seed(data, 1))
        self.assertNotEqual(m.hashlong_128b_with_seed(data, 1),
                            m.hashlong_128b_with_seed(
                                data, 0x9E3779B185EBCA87))

    def test_zero_seed_matches_default(self):
        # The withSeed helper with seed 0 runs the default path.
        import random
        rng = random.Random(17)
        for length in (241, 300, 1024, 2048):
            data = bytes(rng.randrange(256) for _ in range(length))
            self.assertEqual(m.hashlong_128b_with_seed(data, 0),
                             m.hashlong_128b_default(data))

    def test_secret_windows_matter(self):
        # Flipping a byte inside a secret window the function reads
        # changes the result; flipping one outside every window does not.
        data = bytes(range(241))
        base = m._hashlong_128b(data, m.KSECRET)
        for off in (0, 8, 64, 121, 128, 136, 184, 11, 19, 117, 125):
            mutated = bytearray(m.KSECRET)
            mutated[off] ^= 0x01
            self.assertNotEqual(
                m._hashlong_128b(data, bytes(mutated)), base,
                "offset %d should matter" % off)
        mutated = bytearray(m.KSECRET)
        mutated[100] ^= 0x01
        self.assertEqual(
            m._hashlong_128b(data, bytes(mutated)), base,
            "offset 100 is outside every window")

    def test_custom_secret(self):
        # The withSeed helper builds its secret as word 2i += seed,
        # word 2i+1 -= seed; the transliteration and the reference
        # agree on custom secrets too.
        import random
        rng = random.Random(19)
        for length in (241, 512, 2048):
            data = bytes(rng.randrange(256) for _ in range(length))
            self.assertEqual(
                m.hashlong_128b_with_seed(data, 12345),
                m.ref_hashlong_128b_with_seed(data, 12345))
        secret = m._init_custom_secret(7)
        self.assertEqual(secret[:8],
                         (m._u64(m.KSECRET, 0) + 7).to_bytes(8, "little"))
        self.assertEqual(secret[8:16],
                         (m._u64(m.KSECRET, 8) - 7).to_bytes(8, "little"))


class BinaryGroundingTests(unittest.TestCase):
    def test_body_hash_and_secret(self):
        blob = m._read_binary()
        self.assertTrue(m.verify_binary(blob))

    def test_callers_hash(self):
        # ROCKSDB_XXH3_128bits (0x61deab0) and _withSeed (0x61defa0)
        # dispatch len > 240 to these helpers; their bodies match the
        # vendor-census targets.
        blob = m._read_binary()
        for start, end, target in (
                (0x61DEAB0, 0x61DEF95,
                 "065ec95cedd9589b57d746e3ee5b708f3946a71b95ef7f54c428ad23c3a4e077"),
                (0x61DEFA0, 0x61DF516,
                 "180dccff605640ea51e5c1aa5b0c48edf317c92a5e409a64181cc2771d6a54e2")):
            got = hashlib.sha256(blob[start - 0x1000:end - 0x1000]).hexdigest()
            self.assertEqual(got, target)

    def test_result_regenerates(self):
        out = Path(__file__).resolve().parents[1] / "research" / "work-items" \
            / "re-002-node115-xxh3-hashlong-128b-115" / "result.json"
        if not out.exists():
            self.skipTest("result.json not generated yet")
        result = json.loads(out.read_text())
        self.assertEqual(result["total_cases"], 2400)
        self.assertEqual(result["mismatches"], 0)
        self.assertEqual(result["artifact_sha256"], m.ARTIFACT_DIGEST)


if __name__ == "__main__":
    unittest.main()
