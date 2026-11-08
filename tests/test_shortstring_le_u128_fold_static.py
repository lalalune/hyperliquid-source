#!/usr/bin/env python3
"""Static check for packet RE-001-node115-shortstring-le-u128-fold.

Invokes the work-item verifier (which authenticates the node #115 capture by
SHA-256 before any byte interpretation, pins the 89-byte leaf, confirms the GOT
relocations and panic location descriptors, and checks the little-endian u128
fold against an independent pack). Skips when the materialized capture is
absent. The capture is never executed.
"""
import hashlib
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-shortstring-le-u128-fold")
VERIFIER = os.path.join(PACKET, "verify_shortstring_le_u128_fold.py")
BINARY = os.path.join(ROOT, "artifacts/node/115/hl-node")
BIN_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


class ShortStringFoldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(BINARY):
            raise unittest.SkipTest("materialized node115 capture required")
        with open(BINARY, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != BIN_SHA256:
                raise unittest.SkipTest("node115 capture digest mismatch")

    def test_verifier_passes(self):
        r = subprocess.run([sys.executable, "-B", VERIFIER],
                           cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
        self.assertIn("RESULT: PASS", r.stdout)


if __name__ == "__main__":
    unittest.main()
