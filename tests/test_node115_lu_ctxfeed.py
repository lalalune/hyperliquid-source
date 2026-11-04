#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-ctxfeed (static, no execution)."""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PACKET = os.path.join(HERE, "..", "research", "work-items",
                      "RE-001-node115-lu-ctxfeed")
BIN = os.path.join(HERE, "..", "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(HERE, "..", "tools", "node115_lu_ctxfeed.py")

EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032


def va_to_off(va):
    return va - 0x1000


def load_records():
    with open(os.path.join(PACKET, "records.json")) as f:
        return json.load(f)


def load_binary():
    with open(BIN, "rb") as f:
        return f.read()


class CtxFeedTests(unittest.TestCase):
    def test_exhibits_regenerate(self):
        data = load_binary()
        rec = load_records()
        for name, ex in rec["exhibits"].items():
            start = int(ex["range"][0], 16)
            with open(os.path.join(PACKET, name + ".hex")) as f:
                claimed = bytes.fromhex("".join(f.read().split()))
            got = data[va_to_off(start):va_to_off(start) + len(claimed)]
            self.assertEqual(got, claimed, name)
            self.assertEqual(len(claimed), ex["bytes"], name)

    def test_fde_bounds(self):
        data = load_binary()
        self.assertEqual(data[va_to_off(0x63E9CD0):va_to_off(0x63E9CD0) + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(data[va_to_off(0x63EAD50):va_to_off(0x63EAD50) + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(0x63EAD50 - 0x63E9CD0, 4224)

    def test_key_bytes(self):
        data = load_binary()
        self.assertEqual(data[va_to_off(0x63E9D37)], 0x75)  # gate jne
        self.assertEqual(data[va_to_off(0x63E9D5A)], 0xC3)  # single ret
        # Generation dispatch: shr/and/cmp/je/cmp/jne.
        self.assertEqual(
            data[va_to_off(0x63EA0E5):va_to_off(0x63EA0E5) + 4],
            bytes.fromhex("48c1ef1c"))

    def test_feed_collect_targets(self):
        data = load_binary()
        for site in (0x63EA135, 0x63EA495, 0x63EAAD3):
            o = va_to_off(site)
            self.assertEqual(data[o], 0xE8, hex(site))
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            self.assertEqual(site + 5 + rel, 0x6363660, hex(site))
        for site in (0x63EAB9E, 0x63EAC11, 0x63EACF9):
            o = va_to_off(site)
            self.assertEqual(data[o], 0xE8, hex(site))
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            self.assertEqual(site + 5 + rel, 0x6363560, hex(site))

    def test_manifest_coverage(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            entries = [l.split() for l in f if l.strip()]
        paths = {p for _, p in entries}
        self.assertNotIn("MANIFEST.sha256", paths)
        self.assertIn("README.md", paths)
        self.assertIn("EVIDENCE.md", paths)
        self.assertIn("records.json", paths)
        self.assertIn("../../../tools/node115_lu_ctxfeed.py", paths)
        self.assertIn("../../../tests/test_node115_lu_ctxfeed.py", paths)
        for name in load_records()["exhibits"]:
            self.assertIn(name + ".hex", paths)
            self.assertIn(name + ".objdump.txt", paths)
        self.assertEqual(len(entries), 15)

    def test_strict_counts(self):
        rec = load_records()
        total = 0
        for name, ex in rec["exhibits"].items():
            strict = 0
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                for line in f:
                    m = re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+?\t(.*)$", line)
                    if m and m.group(1).strip():
                        strict += 1
            self.assertEqual(strict, ex["strict"], name)
            total += strict
        self.assertEqual(total, 46)

    def test_records_consistency(self):
        rec = load_records()
        self.assertEqual(rec["binary_sha256"], EXPECT_SHA)
        self.assertEqual(rec["binary_size"], EXPECT_SIZE)
        self.assertEqual(rec["fde"]["start"], "0x63e9cd0")
        self.assertEqual(rec["fde"]["end"], "0x63ead50")
        self.assertEqual(rec["fde"]["size"], 4224)
        outgoing = rec["census"]["outgoing_by_target"]
        self.assertEqual(sum(outgoing.values()), 50)
        self.assertEqual(outgoing["0x6363660"], 3)
        self.assertEqual(outgoing["0x6363560"], 3)
        self.assertEqual(rec["census"]["incoming_e8_to_fde"], 56)
        self.assertEqual(rec["census"]["got"], 0)
        self.assertEqual(rec["census"]["rela_dyn_entries"], 60723)
        self.assertEqual(rec["feed_sites"],
                         ["0x63ea135", "0x63ea495", "0x63eaad3"])
        self.assertEqual(rec["collect_sites"],
                         ["0x63eab9e", "0x63eac11", "0x63eacf9"])

    def test_tamper_control(self):
        data = bytearray(load_binary())
        data[va_to_off(0x63E9CD0)] ^= 0xFF
        self.assertNotEqual(
            bytes(data[va_to_off(0x63E9CD0):va_to_off(0x63E9CD0) + 4]),
            bytes.fromhex("f30f1efa"))
        self.assertNotEqual(hashlib.sha256(bytes(data)).hexdigest(),
                            EXPECT_SHA)

    def test_verifier_exit_zero(self):
        r = subprocess.run([sys.executable, VERIFIER],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("all checks passed", r.stdout)


if __name__ == "__main__":
    unittest.main()
