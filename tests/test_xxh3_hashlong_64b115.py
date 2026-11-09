"""Tests for tools/xxh3_hashlong_64b115.py.

Every assertion compares the disassembly transliteration against the
independent loop-form reference, or checks a pinned binary fact (body
hash, immediates, secret table, callers). The check values are computed
values confirmed against the system libxxhash 0.8.2 oracle at the
64-bit entry points during development; they also equal the low64
halves of the 128-bit pair's check values (PR #5598), as the 64-bit
merge is the same low64 merge.
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import xxh3_hashlong_64b115 as m


class HashLong64bTests(unittest.TestCase):
    def test_check_values(self):
        # Computed values, confirmed against the system libxxhash 0.8.2
        # oracle at the 64-bit entry points during development
        # (XXH3_64bits / XXH3_64bits_withSeed, lengths 241..5000:
        # 600/600, 0 mismatches).
        self.assertEqual(m.hashlong_64b_default(bytes(241)),
                         0x5C5B5D5D40C59CE3)
        self.assertEqual(m.hashlong_64b_default(b"a" * 241),
                         0xF6CFEF5C5ACA1930)
        self.assertEqual(m.hashlong_64b_default(
            bytes((j * 7 + 3) & 0xFF for j in range(512))),
            0xF58202B8D9019D1D)
        self.assertEqual(m.hashlong_64b_with_seed(
            bytes(j & 0xFF for j in range(1024)), m.PRIME64_1),
            0xC09766CEA347AAE6)
        self.assertEqual(m.hashlong_64b_with_seed(bytes(241), 1),
                         0x8EF42DD2D1D7A75F)
        self.assertEqual(m.hashlong_64b_with_seed(
            bytes(j & 0xFF for j in range(2048)), 7),
            0x607B46EF2832250A)
        self.assertEqual(m.hashlong_64b_with_seed(
            bytes((j * 13 + 5) & 0xFF for j in range(300)), 0xDEADBEEF),
            0xB33F489CD50CCE5B)

    def test_len_out_of_scope(self):
        with self.assertRaises(ValueError):
            m.hashlong_64b_default(bytes(240))
        with self.assertRaises(ValueError):
            m.hashlong_64b_with_seed(bytes(128), 0)
        with self.assertRaises(ValueError):
            m.hashlong_64b_with_seed(bytes(0), 5)

    def test_agrees_with_reference(self):
        import random
        rng = random.Random(11)
        for length in (241, 242, 256, 300, 512, 1024, 1025, 2048, 4096):
            for _ in range(4):
                data = bytes(rng.randrange(256) for _ in range(length))
                seed = rng.getrandbits(64)
                self.assertEqual(m.hashlong_64b_with_seed(data, seed),
                                 m.ref_hashlong_64b_with_seed(data, seed))
                self.assertEqual(m.hashlong_64b_default(data),
                                 m.ref_hashlong_64b_default(data))

    def test_boundary_lengths(self):
        import random
        rng = random.Random(13)
        for length in (241, 242, 255, 256, 257, 320, 321, 1023, 1024,
                       1025, 1087, 1088, 1089, 2048, 2049):
            data = bytes(rng.randrange(256) for _ in range(length))
            seed = rng.getrandbits(64)
            self.assertEqual(m.hashlong_64b_with_seed(data, seed),
                             m.ref_hashlong_64b_with_seed(data, seed))
            self.assertEqual(m.hashlong_64b_default(data),
                             m.ref_hashlong_64b_default(data))

    def test_seed_changes_output(self):
        data = bytes(range(241))
        self.assertNotEqual(m.hashlong_64b_with_seed(data, 0),
                            m.hashlong_64b_with_seed(data, 1))
        self.assertNotEqual(m.hashlong_64b_with_seed(data, 1),
                            m.hashlong_64b_with_seed(
                                data, 0x9E3779B185EBCA87))

    def test_zero_seed_matches_default(self):
        # The withSeed helper with seed 0 runs the default path.
        import random
        rng = random.Random(17)
        for length in (241, 300, 1024, 2048):
            data = bytes(rng.randrange(256) for _ in range(length))
            self.assertEqual(m.hashlong_64b_with_seed(data, 0),
                             m.hashlong_64b_default(data))

    def test_secret_windows_matter(self):
        # Flipping a byte inside a secret window the function reads
        # changes the result; flipping one outside every window does not.
        # At len 241 there are no full blocks, so the scramble window
        # (secret+128) is not read; offsets 128/136/184 are covered by
        # the last-stripe window (secret+121..185) instead.
        data = bytes(range(241))
        base = m._hashlong_64b(data, m.KSECRET)
        for off in (0, 8, 64, 121, 128, 136, 184, 11, 19):
            mutated = bytearray(m.KSECRET)
            mutated[off] ^= 0x01
            self.assertNotEqual(
                m._hashlong_64b(data, bytes(mutated)), base,
                "offset %d should matter" % off)
        mutated = bytearray(m.KSECRET)
        mutated[100] ^= 0x01
        self.assertEqual(
            m._hashlong_64b(data, bytes(mutated)), base,
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
                m.hashlong_64b_with_seed(data, 12345),
                m.ref_hashlong_64b_with_seed(data, 12345))
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
        # ROCKSDB_XXH3_64bits (0x61db650) and _withSeed (0x61dc0c0)
        # dispatch len > 240 to these helpers; their bodies match the
        # vendor-census targets.
        blob = m._read_binary()
        for start, end, target in (
                (0x61DB650, 0x61DB93A,
                 "adde9328dc4c355cf1410323721f18dea26b8d5508920d127f8cdfdabe5aa3bb"),
                (0x61DC0C0, 0x61DC401,
                 "781a95efaa091e8581fa6cc2cda7770a5b3aa356678e40a07f33ec7922fd088f")):
            got = hashlib.sha256(blob[start - 0x1000:end - 0x1000]).hexdigest()
            self.assertEqual(got, target)

    def test_result_regenerates(self):
        out = Path(__file__).resolve().parents[1] / "research" / "work-items" \
            / "re-002-node115-xxh3-hashlong-64b-115" / "result.json"
        if not out.exists():
            self.skipTest("result.json not generated yet")
        result = json.loads(out.read_text())
        self.assertEqual(result["total_cases"], 2400)
        self.assertEqual(result["mismatches"], 0)
        self.assertEqual(result["artifact_sha256"], m.ARTIFACT_DIGEST)


if __name__ == "__main__":
    unittest.main()
