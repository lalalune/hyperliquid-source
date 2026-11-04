#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-acquire-release-callers.

Byte-level checks only; the node binary is never executed. The full
whole-binary census lives in tools/node115_lu_acquire_release_callers.py
and is exercised separately (verifier exit 0).
"""
import re
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-acquire-release-callers"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def text_bytes(data, va, n):
    return data[va - 0x1000:va - 0x1000 + n]


class TestAcquireReleaseCallers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = BIN.read_bytes()

    def test_excerpts_regenerate(self):
        cases = [
            ("wrapper.hex", 0x2AC0F60, 0x2AC0FB0),
            ("acquire_a.hex", 0x2ACE08B, 0x2ACE0EC),
            ("release_a.hex", 0x2ACEB52, 0x2ACEBA0),
        ]
        for name, start, end in cases:
            raw = bytes.fromhex((PACKET / name).read_text().strip())
            self.assertEqual(raw, text_bytes(self.data, start, end - start),
                             name)

    def test_tamper_control(self):
        raw = bytes.fromhex((PACKET / "wrapper.hex").read_text().strip())
        bad = bytearray(raw)
        bad[0] ^= 0xFF
        self.assertNotEqual(bytes(bad),
                            text_bytes(self.data, 0x2AC0F60, 0x2AC0FB0))

    def test_strict_counts(self):
        cases = [
            ("wrapper.objdump.txt", 27),
            ("acquire_a.objdump.txt", 15),
            ("release_a.objdump.txt", 11),
        ]
        for name, want in cases:
            lines = (PACKET / name).read_text().splitlines()
            count = sum(1 for ln in lines if STRICT_RE.match(ln))
            self.assertEqual(count, want, name)

    def test_wrapper_body_tail_split(self):
        lines = (PACKET / "wrapper.objdump.txt").read_text().splitlines()
        strict = [ln for ln in lines if STRICT_RE.match(ln)]
        body = [ln for ln in strict
                if int(ln.split(":")[0].strip(), 16) <= 0x2AC0F8F]
        tail = [ln for ln in strict
                if int(ln.split(":")[0].strip(), 16) > 0x2AC0F8F]
        self.assertEqual(len(body), 19)
        self.assertEqual(len(tail), 8)
        self.assertIn("ret", body[-1])
        self.assertEqual(text_bytes(self.data, 0x2AC0F8F, 1), b"\xc3")

    def test_got_site_call_bytes(self):
        sites = [
            (0x2ACE0BE, "ff157492a103"), (0x2AD20DA, "ff155852a103"),
            (0x2AA5A79, "ff151118a403"), (0x2AA5C2C, "ff155e16a403"),
            (0x2AA77D9, "ff15b1faa303"), (0x2AA798C, "ff15fef8a303"),
            (0x2AC0F70, "ff151a63a203"), (0x2ACEB7A, "ff151087a103"),
            (0x2ACF336, "ff15547fa103"), (0x2AD06C2, "ff15c86ba103"),
            (0x2AD2B7D, "ff150d47a103"), (0x2AD3303, "ff15873fa103"),
            (0x2AD46CF, "ff15bb2ba103"),
        ]
        slots = {0x2ACE0BE: 0x64E7338, 0x2AD20DA: 0x64E7338}
        for site, want in sites:
            raw = text_bytes(self.data, site, 6)
            self.assertEqual(raw, bytes.fromhex(want), hex(site))
            disp = struct.unpack_from("<i", raw, 2)[0]
            self.assertEqual(site + 6 + disp, slots.get(site, 0x64E7290),
                             hex(site))

    def test_acquire_setups_and_null_branches(self):
        # A: out=rsp+0x180, pcell=r12=[rbx+0x110], input=r15d.
        self.assertEqual(text_bytes(self.data, 0x2ACE0B0, 7),
                         bytes.fromhex("488dbc24800100"))
        self.assertEqual(text_bytes(self.data, 0x2ACE0B8, 3),
                         bytes.fromhex("4c89e6"))
        self.assertEqual(text_bytes(self.data, 0x2ACE0BB, 3),
                         bytes.fromhex("4489fa"))
        # B: out=rsp+0x150, pcell=r15=[rbx+0x110], input=r13d.
        self.assertEqual(text_bytes(self.data, 0x2AD20CC, 7),
                         bytes.fromhex("488dbc24500100"))
        self.assertEqual(text_bytes(self.data, 0x2AD20D4, 3),
                         bytes.fromhex("4c89fe"))
        self.assertEqual(text_bytes(self.data, 0x2AD20D7, 3),
                         bytes.fromhex("4489ea"))
        # NULL branches resolve to the error-log paths.
        for je_va, target in ((0x2ACE0CD, 0x2ACE3C6), (0x2AD20E9, 0x2AD23E7)):
            raw = text_bytes(self.data, je_va, 6)
            self.assertEqual(raw[:2], bytes.fromhex("0f84"))
            disp = struct.unpack_from("<i", raw, 2)[0]
            self.assertEqual(je_va + 6 + disp, target, hex(je_va))
        # Pair install (A) and pair-slot teardown guard (A).
        self.assertEqual(text_bytes(self.data, 0x2ACE5F0, 8),
                         bytes.fromhex("0f28842460010000"))
        self.assertEqual(text_bytes(self.data, 0x2ACE5F8, 7),
                         bytes.fromhex("0f118378020000"))
        self.assertEqual(text_bytes(self.data, 0x2ACFFC0, 7),
                         bytes.fromhex("488dbc24600100"))

    def test_drop_field_template_and_strings(self):
        # Drop FDE field +0xe8: release, dec, free-at-zero.
        self.assertEqual(text_bytes(self.data, 0x2AA5A79, 6),
                         bytes.fromhex("ff151118a403"))
        self.assertEqual(text_bytes(self.data, 0x2AA5A7F, 3),
                         bytes.fromhex("498b07"))
        self.assertEqual(text_bytes(self.data, 0x2AA5A82, 4),
                         bytes.fromhex("f048ff08"))
        self.assertEqual(text_bytes(self.data, 0x2AA5A8F, 6),
                         bytes.fromhex("ff15e317a403"))
        for va, want in (
                (0x60567B, b"closing gossip stream because peer is already connected"),
                (0x605781, b"dropping connection after sending abci state"),
                (0x6056B2, b"node_stream_connection")):
            self.assertEqual(self.data[va:va + len(want)], want, hex(va))

    def test_excerpts_disjoint_from_prior_claims(self):
        priors = [(0x4FAC710, 0x4FAC7E0), (0x4FB52E0, 0x4FB5440),
                  (0x4DA86A0, 0x4DA8860), (0x4DA6C80, 0x4DA6D70)]
        for start, end in [(0x2AC0F60, 0x2AC0FB0), (0x2ACE08B, 0x2ACE0EC),
                           (0x2ACEB52, 0x2ACEBA0)]:
            for p0, p1 in priors:
                self.assertTrue(end <= p0 or start >= p1,
                                f"{start:#x}..{end:#x} overlaps {p0:#x}..{p1:#x}")


if __name__ == "__main__":
    unittest.main()
