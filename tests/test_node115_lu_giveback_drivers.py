#!/usr/bin/env python3
"""Unit tests for the node115 lu give-back drivers packet.

Regeneration comparison + tamper control. objdump's header embeds the
invoked path, so comparisons strip the header lines (as in #224).
"""
import json
import os
import re
import struct
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-giveback-drivers")
BIN = os.path.join(ROOT, "artifacts/node/115/hl-node")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import node115_lu_giveback_drivers as V  # noqa: E402


def text_off(va):
    data = open(BIN, "rb").read()
    secs = V.elf_sections(data)
    return V.va_to_off(secs[".text"], va)


class TestPacket(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rec = json.load(open(os.path.join(PACKET, "records.json")))
        cls.data = open(BIN, "rb").read()
        cls.secs = V.elf_sections(cls.data)

    def test_verifier_passes(self):
        self.assertEqual(V.main(), 0)

    def test_exhibit_bytes_match_binary(self):
        for name, e in self.rec["exhibits"].items():
            lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
            raw = self.data[text_off(lo):text_off(hi)]
            hexlines = "".join(open(os.path.join(PACKET, name + ".hex")).read().split())
            self.assertEqual(bytes.fromhex(hexlines), raw, name)
            self.assertEqual(len(raw), e["bytes"], name)

    def test_exhibit_objdump_regeneration(self):
        for name, e in self.rec["exhibits"].items():
            lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
            regen = V.objdump_range(lo, hi)
            stored = [l for l in open(
                os.path.join(PACKET, name + ".objdump.txt")).read().splitlines()
                if l.strip()]
            self.assertEqual(regen, stored, name)

    def test_strict_counts(self):
        total = 0
        for name, e in self.rec["exhibits"].items():
            lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
            n = len(V.strict_lines(V.objdump_range(lo, hi)))
            self.assertEqual(n, e["strict"], name)
            total += n
        self.assertEqual(total, self.rec["exhibits_total_strict"])
        self.assertEqual(sum(e["bytes"] for e in self.rec["exhibits"].values()),
                         self.rec["exhibits_total_bytes"])

    def test_giveback_call_rel32(self):
        for site in self.rec["census"]["e8_to_giveback"]:
            s = int(site, 16)
            o = text_off(s)
            rel = struct.unpack("<i", self.data[o + 1:o + 5])[0]
            self.assertEqual(self.data[o], 0xE8, site)
            self.assertEqual(s + 5 + rel, 0x63D8E70, site)

    def test_tamper_control(self):
        # Flipping one exhibit byte must break the byte-equality check.
        e = self.rec["exhibits"]["gbD_site"]
        lo = int(e["range"][0], 16)
        raw = bytearray(self.data[text_off(lo):text_off(lo) + e["bytes"]])
        hexlines = "".join(open(
            os.path.join(PACKET, "gbD_site.hex")).read().split())
        self.assertEqual(bytes.fromhex(hexlines), bytes(raw))
        raw[0] ^= 0xFF
        self.assertNotEqual(bytes.fromhex(hexlines), bytes(raw))

    def test_fde_bounds_via_eh_frame(self):
        fdes = V.eh_frame_fdes(self.data, self.secs[".eh_frame"])
        for name, r in self.rec["fdes"].items():
            lo, hi = int(r["range"][0], 16), int(r["range"][1], 16)
            self.assertEqual(fdes.get(lo), hi - lo, name)
            self.assertEqual(r["bytes"], hi - lo, name)

    def test_no_012_store(self):
        for name, r in self.rec["fdes"].items():
            lo, hi = int(r["range"][0], 16), int(r["range"][1], 16)
            for line in V.objdump_range(lo, hi):
                self.assertNotRegex(line, r"0x12\(", (name, line))

    def test_flag_store_bytes(self):
        cases = {0x63B7B06: "66896b13", 0x63B8364: "410f954613",
                 0x63B89FB: "410f954613", 0x63B80B3: "6644894d13"}
        for site, hx in cases.items():
            got = self.data[text_off(site):text_off(site) + len(bytes.fromhex(hx))]
            self.assertEqual(got, bytes.fromhex(hx), hex(site))

    def test_manifest_hashes(self):
        import hashlib
        for line in open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines():
            if not line.strip():
                continue
            digest, rel = line.split(None, 1)
            p = os.path.normpath(os.path.join(PACKET, rel.strip()))
            self.assertTrue(os.path.isfile(p), rel)
            self.assertEqual(hashlib.sha256(open(p, "rb").read()).hexdigest(),
                             digest, rel)


if __name__ == "__main__":
    unittest.main()
