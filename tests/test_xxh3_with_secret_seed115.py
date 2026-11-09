"""Tests for tools/xxh3_with_secret_seed115.py.

The two published anchors are XXH3_64bits(b"", 0) = 0x2d06800538d394c2
and XXH3_64bits(b"a", 0) = 0xe6c632b61e964e1f, checked through both entry
points (withSecret with the default secret, withSeed with seed 0). Every
other assertion compares the disassembly transliteration against the
independent public-formula reference, or checks a pinned binary fact
(body hashes, folded immediates, secret table).
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import xxh3_with_secret_seed115 as m

EMPTY = 0x2D06800538D394C2
A = 0xE6C632B61E964E1F


class WithSecretTests(unittest.TestCase):
    def test_published_empty(self):
        self.assertEqual(m.xxh3_with_secret(b"", m.KSECRET), EMPTY)

    def test_published_a(self):
        self.assertEqual(m.xxh3_with_secret(b"a", m.KSECRET), A)

    def test_secret_offsets_matter(self):
        # Each short branch reads only its own secret windows: flipping a
        # byte inside a window the active branch reads changes the result,
        # flipping one outside every window of that branch does not.
        cases = [
            (b"", (56, 64)),
            (b"ab", (0, 4)),
            (b"abcdef", (8, 16)),
            (bytes(range(16)), (24, 32, 40, 48)),
        ]
        for data, offsets in cases:
            base = m.xxh3_with_secret(data, m.KSECRET)
            for off in offsets:
                mutated = bytearray(m.KSECRET)
                mutated[off] ^= 0x01
                self.assertNotEqual(
                    m.xxh3_with_secret(data, bytes(mutated)), base,
                    "offset %d should matter for len %d" % (off, len(data)))
        mutated = bytearray(m.KSECRET)
        mutated[100] ^= 0x01
        self.assertEqual(
            m.xxh3_with_secret(bytes(range(16)), bytes(mutated)),
            m.xxh3_with_secret(bytes(range(16)), m.KSECRET))

    def test_len_out_of_scope(self):
        with self.assertRaises(ValueError):
            m.xxh3_with_secret(b"x" * 17, m.KSECRET)

    def test_agrees_with_reference(self):
        import random
        rng = random.Random(7)
        for length in range(17):
            for _ in range(20):
                data = bytes(rng.randrange(256) for _ in range(length))
                secret = bytes(rng.randrange(256) for _ in range(192))
                self.assertEqual(m.xxh3_with_secret(data, secret),
                                 m.ref_with_secret(data, secret))


class WithSeedTests(unittest.TestCase):
    def test_published_empty(self):
        self.assertEqual(m.xxh3_with_seed(b"", 0), EMPTY)

    def test_published_a(self):
        self.assertEqual(m.xxh3_with_seed(b"a", 0), A)

    def test_seed_changes_output(self):
        self.assertNotEqual(m.xxh3_with_seed(b"abc", 0),
                            m.xxh3_with_seed(b"abc", 1))
        self.assertNotEqual(m.xxh3_with_seed(b"abc", 1),
                            m.xxh3_with_seed(b"abc", 0x9E3779B185EBCA87))

    def test_len_out_of_scope(self):
        with self.assertRaises(ValueError):
            m.xxh3_with_seed(b"x" * 17, 0)

    def test_agrees_with_reference(self):
        import random
        rng = random.Random(11)
        for length in range(17):
            for _ in range(20):
                data = bytes(rng.randrange(256) for _ in range(length))
                seed = rng.getrandbits(64)
                self.assertEqual(m.xxh3_with_seed(data, seed),
                                 m.ref_with_seed(data, seed))

    def test_zero_secret_seed_equivalence(self):
        # withSeed(data, 0) must equal withSecret(data, kSecret): both run
        # the short branches with the default secret and seed 0.
        import random
        rng = random.Random(13)
        for length in range(17):
            data = bytes(rng.randrange(256) for _ in range(length))
            self.assertEqual(m.xxh3_with_seed(data, 0),
                             m.xxh3_with_secret(data, m.KSECRET))


class BinaryGroundingTests(unittest.TestCase):
    def test_body_hashes_and_secret(self):
        blob = m._read_binary()
        self.assertTrue(m.verify_binary(blob))

    def test_result_regenerates(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            proc = subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parents[1]
                                     / "tools" / "xxh3_with_secret_seed115.py"),
                 "--out", str(out)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads((out / "result.json").read_text())
            self.assertEqual(result["total_cases"], 2400)
            self.assertEqual(result["mismatches"], 0)
            self.assertEqual(len(result["cases"]), 2400)


if __name__ == "__main__":
    unittest.main()
