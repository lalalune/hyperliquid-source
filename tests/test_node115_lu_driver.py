#!/usr/bin/env python3
"""Unit tests for the node #115 lu loop-driver packet
(RE-001-node115-lu-driver).

Regeneration comparison + tamper control; no binary execution.
Objdump header lines embed the invoked path, so saved .objdump.txt
files hold instruction lines only and are compared against the same
filtered lines from a fresh objdump run.
"""

import hashlib
import os
import re
import struct
import subprocess
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-driver")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_driver.py")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

EXHIBITS = {
    "dr_entry": (0x63B8D90, 0x63B8DF0, 96, 28),
    "dr_call1": (0x63B8DF0, 0x63B8E31, 65, 20),
    "dr_lock2": (0x63B8E31, 0x63B8E76, 69, 12),
    "dr_call2": (0x63B8E76, 0x63B8EB3, 61, 17),
    "dr_gate": (0x63B8EB3, 0x63B8ED0, 29, 7),
    "dr_call3": (0x63B8F10, 0x63B8F6A, 90, 22),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:", line)]


class DriverTests(unittest.TestCase):
    def test_binary_sha_and_size(self):
        with open(NODE, "rb") as f:
            data = f.read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), TARGET_SHA)
        self.assertEqual(len(data), TARGET_SIZE)

    def test_exhibits_regenerate(self):
        with open(NODE, "rb") as f:
            data = f.read()
        for name, (start, end, nbytes, _nstrict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".hex")) as f:
                raw = bytes.fromhex("".join(f.read().split()))
            self.assertEqual(len(raw), nbytes, name)
            self.assertEqual(raw, data[start - 0x1000:start - 0x1000 + nbytes], name)
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                saved = [line for line in f.read().splitlines() if line.strip()]
            self.assertEqual(saved, objdump_lines(start, end), name)

    def test_fde_bounds(self):
        with open(NODE, "rb") as f:
            data = f.read()
        # Entry is endbr64.
        self.assertEqual(data[0x63B8D90 - 0x1000:0x63B8D90 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(0x63B8FD1 - 0x63B8D90, 577)
        self.assertEqual(data[0x63B8FD1 - 0x1000], 0xCC)
        self.assertEqual(data[0x63B8DE7 - 0x1000], 0xC3)
        self.assertEqual(data[0x63B8FE0 - 0x1000:0x63B8FE0 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        # First loop call at 0x63b8e1a.
        self.assertEqual(data[off(0x63B8E1A)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B8E1A) + 1)[0]
        self.assertEqual(0x63B8E1A + 5 + rel, 0x63B81B0)
        # Second loop call at 0x63b8e95.
        self.assertEqual(data[off(0x63B8E95)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B8E95) + 1)[0]
        self.assertEqual(0x63B8E95 + 5 + rel, 0x63B81B0)
        # Gate call at 0x63b8ec2.
        self.assertEqual(data[off(0x63B8EC2)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B8EC2) + 1)[0]
        self.assertEqual(0x63B8EC2 + 5 + rel, 0x63B85F0)
        # Completion call at 0x63b8f1a.
        self.assertEqual(data[off(0x63B8F1A)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B8F1A) + 1)[0]
        self.assertEqual(0x63B8F1A + 5 + rel, 0x63D94B0)
        # Third loop call at 0x63b8f4d.
        self.assertEqual(data[off(0x63B8F4D)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B8F4D) + 1)[0]
        self.assertEqual(0x63B8F4D + 5 + rel, 0x63B81B0)
        # LEA site loading the driver address at 0x63b90ea.
        self.assertEqual(data[off(0x63B90EA):off(0x63B90EA) + 3],
                         bytes.fromhex("488d0d"))
        rel = struct.unpack_from("<i", data, off(0x63B90EA) + 3)[0]
        self.assertEqual(0x63B90EA + 7 + rel, 0x63B8D90)
        # Return-value load: mov %r15,%rax at 0x63b8dda.
        self.assertEqual(data[off(0x63B8DDA):off(0x63B8DDA) + 3],
                         bytes.fromhex("4c89f8"))

    def test_strict_counts(self):
        for name, (_s, _e, _b, nstrict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                strict = sum(1 for line in f if STRICT_RE.match(line))
            self.assertEqual(strict, nstrict, name)

    def test_tampered_exhibit_rejected(self):
        with open(NODE, "rb") as f:
            data = f.read()
        with open(os.path.join(PACKET, "dr_gate.hex")) as f:
            raw = bytearray(bytes.fromhex("".join(f.read().split())))
        raw[0] ^= 0xFF
        self.assertNotEqual(bytes(raw),
                            data[0x63B8EB3 - 0x1000:0x63B8EB3 - 0x1000 + 29])

    def test_verifier_passes(self):
        out = subprocess.run(["python3", VERIFIER],
                             capture_output=True, text=True, check=True)
        self.assertIn("all checks passed", out.stdout)

    def test_records_match(self):
        import json
        with open(os.path.join(PACKET, "records.json")) as f:
            rec = json.load(f)
        self.assertEqual(rec["function"]["range"], ["0x63b8d90", "0x63b8fd1"])
        self.assertEqual(rec["function"]["bytes"], 577)
        for name, (start, end, nbytes, nstrict) in EXHIBITS.items():
            ex = rec["exhibits"][name]
            self.assertEqual(ex["range"], [hex(start), hex(end)], name)
            self.assertEqual(ex["bytes"], nbytes, name)
            self.assertEqual(ex["strict"], nstrict, name)
        self.assertEqual(rec["census"]["E8"], [])
        self.assertEqual(rec["census"]["E9"], [])
        self.assertEqual(rec["census"]["LEA"], ["0x63b90ea"])

    def test_manifest_covers_packet(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            entries = [line.split() for line in f if line.strip()]
        self.assertEqual(len(entries), 17)
        for digest, path in entries:
            with open(os.path.normpath(os.path.join(PACKET, path)), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, path)

    def test_no_neighbour_overlap(self):
        fde = (0x63B8D90, 0x63B8FD1)
        neighbours = [(0x63B8820, 0x63B8D85), (0x63B81B0, 0x63B8517),
                      (0x63B8160, 0x63B81AB), (0x63D9340, 0x63D945B),
                      (0x63B9690, 0x63B99C8)]
        for s, e in neighbours:
            self.assertTrue(e <= fde[0] or s >= fde[1], (hex(s), hex(e)))


if __name__ == "__main__":
    unittest.main()
