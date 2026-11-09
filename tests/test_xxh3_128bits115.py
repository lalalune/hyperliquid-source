"""Tests for tools/xxh3_128bits115.py.

The published anchor is XXH3_128bits(b"", 0) = (0x6001c324468d497f,
0x99aa06d3014798d8), checked through both entry points (128bits and
withSeed with seed 0). Every other assertion compares the disassembly
transliteration against the independent public-formula reference, or
checks a pinned binary fact (body hashes, folded immediates, secret
table, caller wrappers).
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import xxh3_128bits115 as m

EMPTY = (0x6001C324468D497F, 0x99AA06D3014798D8)


class Bits128Tests(unittest.TestCase):
    def test_published_empty(self):
        self.assertEqual(m.xxh3_128bits(b""), EMPTY)

    def test_check_values(self):
        # Computed values, confirmed against the system libxxhash 0.8.2
        # oracle during development (3,000 cases, 0 mismatches).
        low, high = m.xxh3_128bits(b"a")
        self.assertEqual((low, high),
                         (0xE6C632B61E964E1F, 0xA96FAF705AF16834))
        low, high = m.xxh3_128bits(b"abc")
        self.assertEqual((low, high),
                         (0x78AF5F94892F3950, 0x06B05AB6733A6185))
        low, high = m.xxh3_128bits(b"123456789")
        self.assertEqual((low, high),
                         (0xE9716427681D5860, 0x33119477EDE5DCD5))

    def test_len_out_of_scope(self):
        with self.assertRaises(ValueError):
            m.xxh3_128bits(b"x" * 129)

    def test_agrees_with_reference(self):
        import random
        rng = random.Random(7)
        for length in range(129):
            for _ in range(6):
                data = bytes(rng.randrange(256) for _ in range(length))
                self.assertEqual(m.xxh3_128bits(data),
                                 m.ref_128bits(data))

    def test_boundary_lengths(self):
        import random
        rng = random.Random(9)
        for length in (16, 17, 32, 33, 64, 65, 96, 97, 128):
            data = bytes(rng.randrange(256) for _ in range(length))
            self.assertEqual(m.xxh3_128bits(data),
                             m.ref_128bits(data))

    def test_secret_windows_matter(self):
        # Each branch reads only its own secret windows: flipping a byte
        # inside a window the active branch reads changes the result,
        # flipping one outside every window of that branch does not.
        cases = [
            (b"", (64, 72, 80, 88)),
            (b"ab", (0, 4, 8, 12)),
            (b"abcdef", (16, 24)),
            (bytes(range(16)), (32, 40, 48, 56)),
            (bytes(range(17)), (0, 8, 16, 24)),
            (bytes(range(100)), (96, 104, 112, 120)),
        ]
        for data, offsets in cases:
            base = m._xxh3_128(data, 0, m.KSECRET)
            for off in offsets:
                mutated = bytearray(m.KSECRET)
                mutated[off] ^= 0x01
                self.assertNotEqual(
                    m._xxh3_128(data, 0, bytes(mutated)), base,
                    "offset %d should matter for len %d" % (off, len(data)))
        mutated = bytearray(m.KSECRET)
        mutated[100] ^= 0x01
        self.assertEqual(
            m._xxh3_128(bytes(range(16)), 0, bytes(mutated)),
            m._xxh3_128(bytes(range(16)), 0, m.KSECRET))
        mutated = bytearray(m.KSECRET)
        mutated[120] ^= 0x01
        self.assertEqual(
            m._xxh3_128(bytes(range(17)), 0, bytes(mutated)),
            m._xxh3_128(bytes(range(17)), 0, m.KSECRET))


class WithSeedTests(unittest.TestCase):
    def test_published_empty(self):
        self.assertEqual(m.xxh3_128bits_with_seed(b"", 0), EMPTY)

    def test_seed_changes_output(self):
        self.assertNotEqual(m.xxh3_128bits_with_seed(b"abc", 0),
                            m.xxh3_128bits_with_seed(b"abc", 1))
        self.assertNotEqual(m.xxh3_128bits_with_seed(b"abc", 1),
                            m.xxh3_128bits_with_seed(
                                b"abc", 0x9E3779B185EBCA87))
        self.assertNotEqual(m.xxh3_128bits_with_seed(bytes(range(100)), 0),
                            m.xxh3_128bits_with_seed(bytes(range(100)), 7))

    def test_len_out_of_scope(self):
        with self.assertRaises(ValueError):
            m.xxh3_128bits_with_seed(b"x" * 129, 0)

    def test_agrees_with_reference(self):
        import random
        rng = random.Random(11)
        for length in range(129):
            for _ in range(6):
                data = bytes(rng.randrange(256) for _ in range(length))
                seed = rng.getrandbits(64)
                self.assertEqual(m.xxh3_128bits_with_seed(data, seed),
                                 m.ref_128bits_with_seed(data, seed))

    def test_zero_seed_equivalence(self):
        # withSeed(data, 0) must equal 128bits(data): both run the
        # branches with the default secret and seed 0.
        import random
        rng = random.Random(13)
        for length in range(129):
            data = bytes(rng.randrange(256) for _ in range(length))
            self.assertEqual(m.xxh3_128bits_with_seed(data, 0),
                             m.xxh3_128bits(data))


class BinaryGroundingTests(unittest.TestCase):
    def test_body_hashes_and_secret(self):
        blob = m._read_binary()
        self.assertTrue(m.verify_binary(blob))

    def test_caller_wrappers_hash(self):
        # rocksdb::Hash2x64 (0x61c3db0) and its seeded sibling
        # (0x61c3de0) call the two entry points; their bodies match the
        # vendor-census targets.
        blob = m._read_binary()
        for start, end, target in (
                (0x61C3DB0, 0x61C3DD3,
                 "cdf83f118dae4ddaabf19ff5fef1f5c12469608c9664d39a3b95b0389165ce3f"),
                (0x61C3DE0, 0x61C3E03,
                 "77d46c5d98d167a3da48e8471c2ded2361ced5e47565abbdc0c11628ab785b7b")):
            got = hashlib.sha256(blob[start - 0x1000:end - 0x1000]).hexdigest()
            self.assertEqual(got, target)

    def test_result_regenerates(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            proc = subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parents[1]
                                     / "tools" / "xxh3_128bits115.py"),
                 "--out", str(out)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads((out / "result.json").read_text())
            self.assertEqual(result["total_cases"], 2400)
            self.assertEqual(result["mismatches"], 0)
            self.assertEqual(len(result["cases"]), 2400)


if __name__ == "__main__":
    unittest.main()
