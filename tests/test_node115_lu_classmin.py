#!/usr/bin/env python3
"""Unit tests for the node #115 lu class-minimum-consumer packet
(RE-001-node115-lu-classmin).

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
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-classmin")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_classmin.py")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

EXHIBITS = {
    "cm_entry": (0x63B8820, 0x63B8874, 84, 20),
    "cm_fetch": (0x63B88DE, 0x63B8923, 69, 16),
    "cm_take": (0x63B8929, 0x63B895C, 51, 12),
    "cm_build": (0x63B895C, 0x63B89C0, 100, 22),
    "cm_give": (0x63B8A3D, 0x63B8A5A, 29, 7),
    "cm_ret": (0x63B8AD0, 0x63B8ADA, 10, 2),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:", line)]


class ClassminTests(unittest.TestCase):
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
        self.assertEqual(data[0x63B8820 - 0x1000:0x63B8820 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(0x63B8D85 - 0x63B8820, 1381)
        self.assertEqual(data[0x63B8D85 - 0x1000], 0xCC)
        self.assertEqual(data[0x63B889F - 0x1000], 0xC3)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        # Class-search call at 0x63b8918.
        self.assertEqual(data[off(0x63B8918)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B8918) + 1)[0]
        self.assertEqual(0x63B8918 + 5 + rel, 0x63D9340)
        # Take call at 0x63b892f.
        self.assertEqual(data[off(0x63B892F)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B892F) + 1)[0]
        self.assertEqual(0x63B892F + 5 + rel, 0x63D8E70)
        # Give-back call at 0x63b8a43.
        self.assertEqual(data[off(0x63B8A43)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B8A43) + 1)[0]
        self.assertEqual(0x63B8A43 + 5 + rel, 0x63D9070)
        # Sequence-stamp store: mov %rcx,0x8(%r14) at 0x63b894d.
        self.assertEqual(data[off(0x63B894D):off(0x63B894D) + 4],
                         bytes.fromhex("49894e08"))
        # Node-embed store: mov %r14,0x18(%r15) at 0x63b89bc.
        self.assertEqual(data[off(0x63B89BC):off(0x63B89BC) + 4],
                         bytes.fromhex("4d897718"))

    def test_strict_counts(self):
        for name, (_s, _e, _b, nstrict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                strict = sum(1 for line in f if STRICT_RE.match(line))
            self.assertEqual(strict, nstrict, name)

    def test_tampered_exhibit_rejected(self):
        with open(NODE, "rb") as f:
            data = f.read()
        with open(os.path.join(PACKET, "cm_take.hex")) as f:
            raw = bytearray(bytes.fromhex("".join(f.read().split())))
        raw[0] ^= 0xFF
        self.assertNotEqual(bytes(raw),
                            data[0x63B8929 - 0x1000:0x63B8929 - 0x1000 + 51])

    def test_verifier_passes(self):
        out = subprocess.run(["python3", VERIFIER],
                             capture_output=True, text=True, check=True)
        self.assertIn("all checks passed", out.stdout)

    def test_records_match(self):
        import json
        with open(os.path.join(PACKET, "records.json")) as f:
            rec = json.load(f)
        self.assertEqual(rec["function"]["range"], ["0x63b8820", "0x63b8d85"])
        self.assertEqual(rec["function"]["bytes"], 1381)
        for name, (start, end, nbytes, nstrict) in EXHIBITS.items():
            ex = rec["exhibits"][name]
            self.assertEqual(ex["range"], [hex(start), hex(end)], name)
            self.assertEqual(ex["bytes"], nbytes, name)
            self.assertEqual(ex["strict"], nstrict, name)
        self.assertEqual(rec["census"]["LEA"], ["0x63b90f5"])
        self.assertEqual(rec["census"]["E8"], [])
        self.assertEqual(rec["census"]["E9"], [])

    def test_manifest_covers_packet(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            entries = [line.split() for line in f if line.strip()]
        self.assertEqual(len(entries), 17)
        for digest, path in entries:
            with open(os.path.normpath(os.path.join(PACKET, path)), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, path)

    def test_no_neighbour_overlap(self):
        fde = (0x63B8820, 0x63B8D85)
        neighbours = [(0x63D9340, 0x63D945B), (0x63B9690, 0x63B99C8),
                      (0x63B81B0, 0x63B85F0), (0x63B0980, 0x63B15E9)]
        for s, e in neighbours:
            self.assertTrue(e <= fde[0] or s >= fde[1], (hex(s), hex(e)))


if __name__ == "__main__":
    unittest.main()
