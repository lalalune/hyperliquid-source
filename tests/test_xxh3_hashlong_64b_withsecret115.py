"""Tests for tools/xxh3_hashlong_64b_withsecret115.py.

Every assertion compares the disassembly transliteration against the
independent loop-form reference, or checks a pinned binary fact (body
hash, immediates, secret table, dispatch sites). The check values are
computed values confirmed against the system libxxhash 0.8.2 oracle at
the withSecret entry point during development; the three kSecret check
values equal PR #5601's default-helper values, as the inline path with
the default secret is the same algorithm.
"""

import hashlib
import json
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import xxh3_hashlong_64b_withsecret115 as m


class HashLong64bWithSecretTests(unittest.TestCase):
    def test_check_values(self):
        # Computed values, confirmed against the system libxxhash 0.8.2
        # oracle at the withSecret entry point during development
        # (XXH3_64bits_withSecret, lengths 241..5000, secret sizes
        # 136..256: 600/600, 0 mismatches; all 7 check values confirmed).
        self.assertEqual(m.hashlong_64b_with_secret(bytes(241), m.KSECRET),
                         0x5C5B5D5D40C59CE3)
        self.assertEqual(m.hashlong_64b_with_secret(b"a" * 241, m.KSECRET),
                         0xF6CFEF5C5ACA1930)
        self.assertEqual(m.hashlong_64b_with_secret(
            bytes((j * 7 + 3) & 0xFF for j in range(512)), m.KSECRET),
            0xF58202B8D9019D1D)
        self.assertEqual(m.hashlong_64b_with_secret(
            bytes(j & 0xFF for j in range(1024)), m._secret_136()),
            0x63CBCD2B4958DD0A)
        self.assertEqual(m.hashlong_64b_with_secret(
            bytes(j & 0xFF for j in range(2048)), m._secret_256()),
            0xC1C6749059E203AB)
        self.assertEqual(m.hashlong_64b_with_secret(
            bytes((j * 13 + 5) & 0xFF for j in range(300)), m._secret_160()),
            0xB2FC8292D62D577D)
        self.assertEqual(m.hashlong_64b_with_secret(
            bytes(1024), m._secret_160()),
            0xF73FA2C59D941B2D)

    def test_len_out_of_scope(self):
        with self.assertRaises(ValueError):
            m.hashlong_64b_with_secret(bytes(240), m.KSECRET)
        with self.assertRaises(ValueError):
            m.hashlong_64b_with_secret(bytes(128), m.KSECRET)
        with self.assertRaises(ValueError):
            m.hashlong_64b_with_secret(bytes(0), m.KSECRET)
        with self.assertRaises(ValueError):
            m.hashlong_64b_with_secret(bytes(241), bytes(135))
        with self.assertRaises(ValueError):
            m.hashlong_64b_with_secret(bytes(241), bytes(64))

    def test_agrees_with_reference(self):
        rng = random.Random(11)
        secrets = [m.KSECRET, m._secret_136(), m._secret_160(),
                   m._secret_256(),
                   bytes(rng.randrange(256) for _ in range(192))]
        for length in (241, 242, 256, 300, 512, 1024, 1025, 2048, 4096):
            for secret in secrets:
                data = bytes(rng.randrange(256) for _ in range(length))
                self.assertEqual(
                    m.hashlong_64b_with_secret(data, secret),
                    m.ref_hashlong_64b_with_secret(data, secret))

    def test_boundary_lengths(self):
        rng = random.Random(13)
        # 192-byte secret: block boundary at 1024; 136-byte secret:
        # block boundary at 576; 256-byte secret: block boundary at 1536.
        for length in (241, 242, 255, 256, 257, 320, 321, 575, 576, 577,
                       640, 641, 1023, 1024, 1025, 1087, 1088, 1089,
                       1535, 1536, 1537, 2048, 2049):
            data = bytes(rng.randrange(256) for _ in range(length))
            for secret in (m.KSECRET, m._secret_136(), m._secret_256()):
                self.assertEqual(
                    m.hashlong_64b_with_secret(data, secret),
                    m.ref_hashlong_64b_with_secret(data, secret))

    def test_secret_changes_output(self):
        data = bytes(range(241))
        base = m.hashlong_64b_with_secret(data, m.KSECRET)
        mutated = bytearray(m.KSECRET)
        mutated[0] ^= 0x01
        self.assertNotEqual(
            m.hashlong_64b_with_secret(data, bytes(mutated)), base)
        self.assertNotEqual(
            m.hashlong_64b_with_secret(data, m._secret_136()), base)
        self.assertNotEqual(
            m.hashlong_64b_with_secret(data, m._secret_256()), base)

    def test_ksecret_matches_default_helper_values(self):
        # With the default secret the inline path is the same algorithm
        # as PR #5601's default helper: its three check values hold here.
        self.assertEqual(m.hashlong_64b_with_secret(bytes(241), m.KSECRET),
                         0x5C5B5D5D40C59CE3)
        self.assertEqual(m.hashlong_64b_with_secret(b"a" * 241, m.KSECRET),
                         0xF6CFEF5C5ACA1930)
        self.assertEqual(m.hashlong_64b_with_secret(
            bytes((j * 7 + 3) & 0xFF for j in range(512)), m.KSECRET),
            0xF58202B8D9019D1D)

    def test_secret_windows_matter(self):
        # Flipping a byte inside a secret window the function reads
        # changes the result; flipping one outside every window does not.
        # At len 241 with a 192-byte secret there are no full blocks, so
        # the scramble window (secret+128) is not read; offsets 128/136/
        # 184 are covered by the last-stripe window (secret+121..185)
        # instead. Offset 100 is outside every window at this length.
        data = bytes(range(241))
        base = m.hashlong_64b_with_secret(data, m.KSECRET)
        for off in (0, 8, 64, 121, 128, 136, 184, 11, 19):
            mutated = bytearray(m.KSECRET)
            mutated[off] ^= 0x01
            self.assertNotEqual(
                m.hashlong_64b_with_secret(data, bytes(mutated)), base,
                "offset %d should matter" % off)
        mutated = bytearray(m.KSECRET)
        mutated[100] ^= 0x01
        self.assertEqual(
            m.hashlong_64b_with_secret(data, bytes(mutated)), base,
            "offset 100 is outside every window")

    def test_secret_size_geometry(self):
        # A longer secret changes the block geometry (secretLimit - 64
        # stripes per block): at len 2000 the 136-byte secret runs 3
        # full blocks of 9 stripes, the 256-byte secret 1 block of 24.
        data = bytes((j * 3 + 1) & 0xFF for j in range(2000))
        for secret in (m._secret_136(), m._secret_160(), m.KSECRET,
                       m._secret_256()):
            self.assertEqual(
                m.hashlong_64b_with_secret(data, secret),
                m.ref_hashlong_64b_with_secret(data, secret))


class BinaryGroundingTests(unittest.TestCase):
    def test_body_hash_and_secret(self):
        blob = m._read_binary()
        self.assertTrue(m.verify_binary(blob))

    def test_dispatch_sites(self):
        # The entry point's dispatch: cmp $0x80 at 0x61db9e2 (17..128),
        # cmp $0xf0 at 0x61db9f2 (129..240), the E9 to the len_129to240
        # helper at 0x61dc03a, and the inline entry lea at 0x61db9ff.
        blob = m._read_binary()
        body = blob[m.WITHSECRET_START - 0x1000:m.WITHSECRET_END - 0x1000]
        self.assertEqual(body[0x61db9e2 - m.WITHSECRET_START:
                              0x61db9e2 - m.WITHSECRET_START + 7],
                         bytes.fromhex("4881fe80000000"))
        self.assertEqual(body[0x61db9f2 - m.WITHSECRET_START:
                              0x61db9f2 - m.WITHSECRET_START + 7],
                         bytes.fromhex("4881fef0000000"))
        self.assertEqual(body[0x61dc03a - m.WITHSECRET_START:
                              0x61dc03a - m.WITHSECRET_START + 5],
                         bytes.fromhex("e981bdffff"))
        self.assertEqual(body[0x61db9ff - m.WITHSECRET_START:
                              0x61db9ff - m.WITHSECRET_START + 4],
                         bytes.fromhex("488d49c0"))

    def test_no_in_binary_caller(self):
        # Whole-.text E8/lea scan finds no call site or reference to
        # the withSecret entry point (the binary is stripped).
        import struct
        blob = m._read_binary()
        t0, t1 = 0x1419300, 0x63F0A00
        seg = blob[t0 - 0x1000:t1 - 0x1000]
        target = m.WITHSECRET_START
        for i in range(len(seg) - 8):
            if seg[i] == 0xE8:
                rel = struct.unpack_from("<i", seg, i + 1)[0]
                self.assertNotEqual(t0 + i + 5 + rel, target,
                                    "E8 call at 0x%x" % (t0 + i))
            if seg[i] in (0x48, 0x4C) and seg[i + 1] == 0x8D \
                    and (seg[i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", seg, i + 3)[0]
                self.assertNotEqual(t0 + i + 7 + disp, target,
                                    "lea at 0x%x" % (t0 + i))

    def test_result_regenerates(self):
        out = Path(__file__).resolve().parents[1] / "research" / "work-items" \
            / "re-002-node115-xxh3-hashlong-64b-withsecret-115" / "result.json"
        if not out.exists():
            self.skipTest("result.json not generated yet")
        result = json.loads(out.read_text())
        self.assertEqual(result["total_cases"], 2400)
        self.assertEqual(result["mismatches"], 0)
        self.assertEqual(result["artifact_sha256"], m.ARTIFACT_DIGEST)


if __name__ == "__main__":
    unittest.main()
