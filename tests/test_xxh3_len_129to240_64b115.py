"""Tests for tools/xxh3_len_129to240_64b115.py.

Every assertion compares the disassembly transliteration against the
independent loop-form reference, or checks a pinned binary fact (body
hash, immediates, secret table, callers). The check values are computed
values confirmed against the system libxxhash 0.8.2 oracle at the
64-bit entry points during development.
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import xxh3_len_129to240_64b115 as m


class Len129To240Tests(unittest.TestCase):
    def test_check_values(self):
        # Computed values, confirmed against the system libxxhash 0.8.2
        # oracle at the 64-bit entry points during development
        # (native execution of the extracted bytes: 1,296 cases,
        # 0 mismatches; oracle: 772/772 at the entry points).
        self.assertEqual(m.xxh3_len_129to240(bytes(129), 0),
                         0x37F7943EB2F51359)
        self.assertEqual(m.xxh3_len_129to240(b"a" * 240, 0),
                         0x993C46D96A01B5C6)
        self.assertEqual(m.xxh3_len_129to240(
            bytes((j * 7 + 3) & 0xFF for j in range(160)), 0),
            0xD70DEA8DE694B883)
        self.assertEqual(m.xxh3_len_129to240(
            bytes((j * 7 + 3) & 0xFF for j in range(160)), 7),
            0x3D36C5450F42F176)
        self.assertEqual(m.xxh3_len_129to240(bytes(240), 1),
                         0x8D2D5FEF87725B8B)
        self.assertEqual(m.xxh3_len_129to240(
            bytes(j & 0xFF for j in range(200)), m.PRIME64_1),
            0x4F12BCED2BB7579B)

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
        for length in (129, 130, 143, 144, 159, 160, 161, 175, 176,
                       191, 192, 193, 207, 208, 223, 224, 225, 239, 240):
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
        # The 64bits entry point calls this helper with seed 0; the
        # withSeed entry point with seed 0 must give the same result.
        import random
        rng = random.Random(13)
        for length in (129, 160, 200, 240):
            data = bytes(rng.randrange(256) for _ in range(length))
            self.assertEqual(m.xxh3_len_129to240(data, 0),
                             m.len_129to240_64b(data, m.KSECRET, 0))

    def test_secret_windows_matter(self):
        # Flipping a byte inside a secret window the function reads
        # changes the result; flipping one outside every window does not.
        # Windows read: front secret+0..127, middle +3..114, trailing
        # +119..134; bytes 135..191 are never read.
        data = bytes(range(200))
        base = m.xxh3_len_129to240(data, 0)
        for off in (0, 8, 16, 112, 127, 3, 19, 35, 67, 99, 119, 127, 134):
            mutated = bytearray(m.KSECRET)
            mutated[off] ^= 0x01
            self.assertNotEqual(
                m.len_129to240_64b(data, bytes(mutated), 0), base,
                "offset %d should matter" % off)
        mutated = bytearray(m.KSECRET)
        mutated[140] ^= 0x01
        self.assertEqual(
            m.len_129to240_64b(data, bytes(mutated), 0), base,
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
                m.len_129to240_64b(data, secret, 12345),
                m._ref_len_129to240_64b(data, secret, 12345))


class BinaryGroundingTests(unittest.TestCase):
    def test_body_hash_and_secret(self):
        blob = m._read_binary()
        self.assertTrue(m.verify_binary(blob))

    def test_callers_hash(self):
        # ROCKSDB_XXH3_64bits (0x61db650), _withSecret (0x61db940) and
        # _withSeed (0x61dc0c0) tail-jump to this helper; their bodies
        # match the vendor-census targets.
        blob = m._read_binary()
        for start, end, target in (
                (0x61DB650, 0x61DB93A,
                 "adde9328dc4c355cf1410323721f18dea26b8d5508920d127f8cdfdabe5aa3bb"),
                (0x61DB940, 0x61DC0BC,
                 "af7eebcfc41edea9d250273df385394d8ab58bb4a3bca1d9acae4e3e545ada58"),
                (0x61DC0C0, 0x61DC401,
                 "781a95efaa091e8581fa6cc2cda7770a5b3aa356678e40a07f33ec7922fd088f")):
            got = hashlib.sha256(blob[start - 0x1000:end - 0x1000]).hexdigest()
            self.assertEqual(got, target)

    def test_result_regenerates(self):
        out = Path(__file__).resolve().parents[1] / "research" / "work-items" \
            / "re-002-node115-xxh3-len-129to240-64b-115" / "result.json"
        if not out.exists():
            self.skipTest("result.json not generated yet")
        result = json.loads(out.read_text())
        self.assertEqual(result["total_cases"], 2400)
        self.assertEqual(result["mismatches"], 0)
        self.assertEqual(result["artifact_sha256"], m.ARTIFACT_DIGEST)


if __name__ == "__main__":
    unittest.main()
