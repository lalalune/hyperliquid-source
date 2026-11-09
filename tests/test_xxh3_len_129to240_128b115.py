"""Tests for tools/xxh3_len_129to240_128b115.py.

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

import xxh3_len_129to240_128b115 as m


class Len129To240Tests(unittest.TestCase):
    def test_check_values(self):
        # Computed values, confirmed against the system libxxhash 0.8.2
        # oracle at the 128-bit entry points during development
        # (native execution of the extracted bytes: 3,000 cases,
        # 0 mismatches; oracle: 80/80 at the entry points).
        low, high = m.xxh3_len_129to240(bytes(129), 0)
        self.assertEqual((low, high),
                         (0xDD4911635F2C7A91, 0x5DC489D54B6D88D4))
        low, high = m.xxh3_len_129to240(b"a" * 240, 0)
        self.assertEqual((low, high),
                         (0xEA57D24533760A39, 0x0163721CDAFDE206))
        low, high = m.xxh3_len_129to240(
            bytes((j * 7 + 3) & 0xFF for j in range(160)), 0)
        self.assertEqual((low, high),
                         (0x0E298E02860A8FD0, 0xD71519A37CB75AB6))
        low, high = m.xxh3_len_129to240(
            bytes((j * 7 + 3) & 0xFF for j in range(160)), 7)
        self.assertEqual((low, high),
                         (0x622BB3633ED321EC, 0xC0D0976A5421F6F7))
        low, high = m.xxh3_len_129to240(bytes(240), 1)
        self.assertEqual((low, high),
                         (0xE194B0AFEF365F37, 0x27C2D28FFAB51ED2))
        low, high = m.xxh3_len_129to240(
            bytes(j & 0xFF for j in range(200)), m.PRIME64_1)
        self.assertEqual((low, high),
                         (0x68ECC42DD071D56B, 0x0F52152E04BDF33B))

    def test_len_out_of_scope(self):
        with self.assertRaises(ValueError):
            m.xxh3_len_129to240(bytes(128), 0)
        with self.assertRaises(ValueError):
            m.xxh3_len_129to240(bytes(241), 0)

    def test_agrees_with_reference(self):
        import random
        rng = random.Random(7)
        for length in range(129, 241):
            for _ in range(4):
                data = bytes(rng.randrange(256) for _ in range(length))
                seed = rng.getrandbits(64)
                self.assertEqual(m.xxh3_len_129to240(data, seed),
                                 m.ref_len_129to240(data, seed))

    def test_boundary_lengths(self):
        import random
        rng = random.Random(9)
        for length in (129, 130, 159, 160, 161, 191, 192, 193,
                       223, 224, 225, 239, 240):
            data = bytes(rng.randrange(256) for _ in range(length))
            seed = rng.getrandbits(64)
            self.assertEqual(m.xxh3_len_129to240(data, seed),
                             m.ref_len_129to240(data, seed))

    def test_seed_changes_output(self):
        data = bytes(range(200))
        self.assertNotEqual(m.xxh3_len_129to240(data, 0),
                            m.xxh3_len_129to240(data, 1))
        self.assertNotEqual(m.xxh3_len_129to240(data, 1),
                            m.xxh3_len_129to240(data, 0x9E3779B185EBCA87))

    def test_zero_seed_matches_default_call(self):
        # The 128bits entry point calls this helper with seed 0; the
        # withSeed entry point with seed 0 must give the same result.
        import random
        rng = random.Random(13)
        for length in (129, 160, 200, 240):
            data = bytes(rng.randrange(256) for _ in range(length))
            self.assertEqual(m.xxh3_len_129to240(data, 0),
                             m.len_129to240_128b(data, m.KSECRET, 0))

    def test_secret_windows_matter(self):
        # Flipping a byte inside a secret window the function reads
        # changes the result; flipping one outside every window does not.
        data = bytes(range(200))
        base = m.xxh3_len_129to240(data, 0)
        for off in (0, 8, 16, 112, 3, 19, 35, 67, 103, 111, 119, 127):
            mutated = bytearray(m.KSECRET)
            mutated[off] ^= 0x01
            self.assertNotEqual(
                m.len_129to240_128b(data, bytes(mutated), 0), base,
                "offset %d should matter" % off)
        mutated = bytearray(m.KSECRET)
        mutated[140] ^= 0x01
        self.assertEqual(
            m.len_129to240_128b(data, bytes(mutated), 0), base,
            "offset 140 is outside every window")

    def test_custom_secret(self):
        # The helper takes any 192-byte secret; the transliteration and
        # the reference agree on custom secrets too.
        import random
        rng = random.Random(17)
        secret = bytes(rng.randrange(256) for _ in range(192))
        for length in (129, 175, 240):
            data = bytes(rng.randrange(256) for _ in range(length))
            self.assertEqual(
                m.len_129to240_128b(data, secret, 12345),
                m._ref_len_129to240_128b(data, secret, 12345))


class BinaryGroundingTests(unittest.TestCase):
    def test_body_hash_and_secret(self):
        blob = m._read_binary()
        self.assertTrue(m.verify_binary(blob))

    def test_callers_hash(self):
        # ROCKSDB_XXH3_128bits (0x61deab0) and _withSeed (0x61defa0) call
        # this helper; their bodies match the vendor-census targets.
        blob = m._read_binary()
        for start, end, target in (
                (0x61DEAB0, 0x61DEF95,
                 "065ec95cedd9589b57d746e3ee5b708f3946a71b95ef7f54c428ad23c3a4e077"),
                (0x61DEFA0, 0x61DF516,
                 "180dccff605640ea51e5c1aa5b0c48edf317c92a5e409a64181cc2771d6a54e2")):
            got = hashlib.sha256(blob[start - 0x1000:end - 0x1000]).hexdigest()
            self.assertEqual(got, target)

    def test_result_regenerates(self):
        import subprocess
        out = Path(__file__).resolve().parents[1] / "research" / "work-items" \
            / "re-002-node115-xxh3-len-129to240-128b-115" / "result.json"
        if not out.exists():
            self.skipTest("result.json not generated yet")
        result = json.loads(out.read_text())
        self.assertEqual(result["total_cases"], 2400)
        self.assertEqual(result["mismatches"], 0)
        self.assertEqual(result["artifact_sha256"], m.ARTIFACT_DIGEST)


if __name__ == "__main__":
    unittest.main()
