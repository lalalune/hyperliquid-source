#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-workers (packet #209).

Regeneration, tamper control, strict counts, key bytes, FDE
boundaries, .rela.dyn GOT absence, census spot checks, MANIFEST
coverage. Static byte checks only; the node binary is never run.
"""

import hashlib
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import node115_lu_workers as V

PACKET_DIR = V.PACKET_DIR
STRICT_RE = V.STRICT_RE


class TestWorkers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = V.load_binary()

    def test_regenerate(self):
        for name, start, end, _ in V.EXCERPTS:
            raw = V.va_bytes(self.data, start, end - start)
            with open(os.path.join(PACKET_DIR, name + ".hex"),
                      encoding="utf-8") as f:
                claimed = bytes.fromhex("".join(f.read().split()))
            self.assertEqual(claimed, raw, name)
            body = V.objdump_body(start, end)
            with open(os.path.join(PACKET_DIR, name + ".objdump.txt"),
                      encoding="utf-8") as f:
                self.assertEqual(f.read().splitlines(), body, name)

    def test_tamper_control(self):
        # Flipping one byte in a copy must break the matching check.
        bad = bytearray(self.data)
        off = 0x63C1930 - 0x1000
        bad[off] ^= 0xFF
        self.assertNotEqual(bytes(bad[off:off + 4]), b"\xf3\x0f\x1e\xfa")
        # The real binary still passes the same check.
        self.assertEqual(V.va_bytes(self.data, 0x63C1930, 4),
                         b"\xf3\x0f\x1e\xfa")

    def test_strict_counts(self):
        for name, start, end, strict in V.EXCERPTS:
            body = V.objdump_body(start, end)
            got = sum(1 for ln in body if STRICT_RE.match(ln))
            self.assertEqual(got, strict, name)

    def test_key_bytes(self):
        for va, hexstr in V.KEY_BYTES:
            got = V.va_bytes(self.data, va,
                             len(bytes.fromhex(hexstr))).hex()
            self.assertEqual(got, hexstr, "%#x" % va)

    def test_fde_boundaries(self):
        # Worker starts are endbr64; worker rets are c3; callee gate
        # start is a push prologue (no endbr64 is claimed for it).
        self.assertEqual(V.va_bytes(self.data, 0x63C1930, 4),
                         b"\xf3\x0f\x1e\xfa")
        self.assertEqual(V.va_bytes(self.data, 0x63C19A0, 4),
                         b"\xf3\x0f\x1e\xfa")
        self.assertEqual(V.va_bytes(self.data, 0x63C199C, 1), b"\xc3")
        self.assertEqual(V.va_bytes(self.data, 0x63C1A54, 1), b"\xc3")
        self.assertEqual(V.va_bytes(self.data, 0x63C1030, 2), b"\x41\x57")

    def test_rela_dyn_got_absence(self):
        _, _, _, got = V.census(self.data)
        self.assertEqual(got, [])

    def test_census_spot(self):
        e8, e9, lea, _ = V.census(self.data)
        self.assertEqual(e8[0x63C19A0],
                         [0x635FBD8, 0x6360F7C, 0x63611EF, 0x63C1BFC])
        self.assertEqual(e8[0x63C1930], [0x635FC71, 0x63610A4])
        self.assertEqual(e9[0x63C19A0], [])
        self.assertEqual(e9[0x63C1930], [])
        self.assertEqual(lea[0x63C19A0], [])
        self.assertEqual(lea[0x63C1930], [])

    def test_manifest_coverage(self):
        ok, msg = V.check_manifest()
        self.assertTrue(ok, msg)
        with open(os.path.join(PACKET_DIR, "MANIFEST.sha256"),
                  encoding="utf-8") as f:
            paths = [ln.split(None, 1)[1].strip()
                     for ln in f if ln.strip()]
        for name, _, _, _ in V.EXCERPTS:
            self.assertIn(name + ".hex", paths)
            self.assertIn(name + ".objdump.txt", paths)
        for extra in ("README.md", "EVIDENCE.md", "records.json",
                      "../../../tools/node115_lu_workers.py",
                      "../../../tests/test_node115_lu_workers.py"):
            self.assertIn(extra, paths)


if __name__ == "__main__":
    unittest.main()
