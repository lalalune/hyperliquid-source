#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-slotinsert.

Stdlib unittest only (pytest is not installed in this environment).
All checks are read-only against the node #115 binary; nothing executes.
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PACKET = os.path.join(HERE, "..", "research", "work-items",
                      "RE-001-node115-lu-slotinsert")
BIN = os.path.join(HERE, "..", "artifacts", "node", "115", "hl-node")
TOOL = os.path.join(HERE, "..", "tools", "node115_lu_slotinsert.py")

EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032


def read_binary():
    with open(BIN, "rb") as f:
        return f.read()


def strict_count(path):
    n = 0
    with open(path) as f:
        for line in f:
            m = re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+?\t(.*)$", line)
            if m and m.group(1).strip():
                n += 1
    return n


class SlotInsertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = read_binary()
        with open(os.path.join(PACKET, "records.json")) as f:
            cls.rec = json.load(f)

    def test_binary_sha_and_size(self):
        self.assertEqual(len(self.data), EXPECT_SIZE)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), EXPECT_SHA)

    def test_verifier_exit_zero(self):
        r = subprocess.run(["python3", TOOL], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("all checks passed", r.stdout)

    def test_exhibits_regenerate(self):
        for name, ex in self.rec["exhibits"].items():
            start = int(ex["range"][0], 16)
            end = int(ex["range"][1], 16)
            with open(os.path.join(PACKET, name + ".hex")) as f:
                claimed = bytes.fromhex("".join(f.read().split()))
            self.assertEqual(len(claimed), end - start)
            self.assertEqual(claimed,
                             self.data[start - 0x1000:start - 0x1000 + len(claimed)])

    def test_tamper_control(self):
        with open(os.path.join(PACKET, "si_entry.hex")) as f:
            claimed = bytes.fromhex("".join(f.read().split()))
        tampered = bytes([claimed[0] ^ 0xFF]) + claimed[1:]
        self.assertNotEqual(
            tampered, self.data[0x63AC0D0 - 0x1000:0x63AC0D0 - 0x1000 + len(claimed)])

    def test_strict_counts(self):
        for name, ex in self.rec["exhibits"].items():
            self.assertEqual(
                strict_count(os.path.join(PACKET, name + ".objdump.txt")),
                ex["strict"], name)

    def test_key_bytes(self):
        def at(va, n):
            return self.data[va - 0x1000:va - 0x1000 + n]
        self.assertEqual(at(0x63AC0D0, 4), bytes.fromhex("f30f1efa"))
        self.assertEqual(at(0x63AC177, 5), bytes.fromhex("f34c0fbce5"))
        self.assertEqual(at(0x63AC16E, 1), b"\xc3")
        self.assertEqual(at(0x63AC443, 1), b"\xc3")
        self.assertEqual(at(0x636A035, 5), bytes.fromhex("e896200400"))

    def test_fde_bounds(self):
        fde = self.rec["insert_fde"]
        self.assertEqual(fde["start"], "0x63ac0d0")
        self.assertEqual(fde["end"], "0x63ac472")
        self.assertEqual(fde["size_bytes"], 930)

    def test_census_spot(self):
        self.assertEqual(self.rec["census"]["insert_e8_count"], 6)
        self.assertEqual(self.rec["census"]["insert_e9"], [])
        self.assertEqual(self.rec["census"]["insert_got"], [])

    def test_manifest_coverage(self):
        n = 0
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                digest, _, path = line.partition("  ")
                full = os.path.normpath(os.path.join(PACKET, path))
                with open(full, "rb") as fh:
                    self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), digest)
                n += 1
        self.assertEqual(n, 15)


if __name__ == "__main__":
    unittest.main()
