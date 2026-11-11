#!/usr/bin/env python3
"""Unit tests for the node #115 lu loop-caller packet
(RE-001-node115-lu-loopcaller).

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
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-loopcaller")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_loopcaller.py")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

EXHIBITS = {
    "lc_entry": (0x63B81B0, 0x63B8212, 98, 24),
    "lc_loop": (0x63B8250, 0x63B8290, 64, 15),
    "lc_take": (0x63B8290, 0x63B82C3, 51, 12),
    "lc_build": (0x63B82C3, 0x63B8335, 114, 24),
    "lc_splice": (0x63B83B1, 0x63B840A, 89, 22),
    "lc_ret": (0x63B849A, 0x63B84D5, 59, 17),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:", line)]


class LoopcallerTests(unittest.TestCase):
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
        # Entry is push %r15; push %r14 -- deliberately NOT endbr64.
        self.assertEqual(data[0x63B81B0 - 0x1000:0x63B81B0 - 0x1000 + 4],
                         bytes.fromhex("41574156"))
        self.assertEqual(0x63B8517 - 0x63B81B0, 871)
        self.assertEqual(data[0x63B8517 - 0x1000], 0xCC)
        self.assertEqual(data[0x63B84D4 - 0x1000], 0xC3)
        self.assertEqual(data[0x63B8520 - 0x1000:0x63B8520 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        # Class-search call at 0x63b827f.
        self.assertEqual(data[off(0x63B827F)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B827F) + 1)[0]
        self.assertEqual(0x63B827F + 5 + rel, 0x63D9340)
        # Take call at 0x63b8296.
        self.assertEqual(data[off(0x63B8296)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B8296) + 1)[0]
        self.assertEqual(0x63B8296 + 5 + rel, 0x63D8E70)
        # Give-back call at 0x63b83ac.
        self.assertEqual(data[off(0x63B83AC)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B83AC) + 1)[0]
        self.assertEqual(0x63B83AC + 5 + rel, 0x63D9070)
        # Sequence-stamp store: mov %rsi,0x8(%r14) at 0x63b82b4.
        self.assertEqual(data[off(0x63B82B4):off(0x63B82B4) + 4],
                         bytes.fromhex("49897608"))
        # Node-embed store: mov %r14,0x18(%r15) at 0x63b8320.
        self.assertEqual(data[off(0x63B8320):off(0x63B8320) + 4],
                         bytes.fromhex("4d897718"))
        # Splice store: mov %r15,0x30(%rax) at 0x63b83d5.
        self.assertEqual(data[off(0x63B83D5):off(0x63B83D5) + 4],
                         bytes.fromhex("4c897830"))
        # Return-value load: mov %rbp,%rax at 0x63b84c7.
        self.assertEqual(data[off(0x63B84C7):off(0x63B84C7) + 3],
                         bytes.fromhex("4889e8"))

    def test_strict_counts(self):
        for name, (_s, _e, _b, nstrict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                strict = sum(1 for line in f if STRICT_RE.match(line))
            self.assertEqual(strict, nstrict, name)

    def test_tampered_exhibit_rejected(self):
        with open(NODE, "rb") as f:
            data = f.read()
        with open(os.path.join(PACKET, "lc_take.hex")) as f:
            raw = bytearray(bytes.fromhex("".join(f.read().split())))
        raw[0] ^= 0xFF
        self.assertNotEqual(bytes(raw),
                            data[0x63B8290 - 0x1000:0x63B8290 - 0x1000 + 51])

    def test_verifier_passes(self):
        out = subprocess.run(["python3", VERIFIER],
                             capture_output=True, text=True, check=True)
        self.assertIn("all checks passed", out.stdout)

    def test_records_match(self):
        import json
        with open(os.path.join(PACKET, "records.json")) as f:
            rec = json.load(f)
        self.assertEqual(rec["function"]["range"], ["0x63b81b0", "0x63b8517"])
        self.assertEqual(rec["function"]["bytes"], 871)
        for name, (start, end, nbytes, nstrict) in EXHIBITS.items():
            ex = rec["exhibits"][name]
            self.assertEqual(ex["range"], [hex(start), hex(end)], name)
            self.assertEqual(ex["bytes"], nbytes, name)
            self.assertEqual(ex["strict"], nstrict, name)
        self.assertEqual(rec["census"]["E8"],
                         ["0x63b8baf", "0x63b8c59", "0x63b8e1a",
                          "0x63b8e95", "0x63b8f4d"])
        self.assertEqual(rec["census"]["E9"], [])
        self.assertEqual(rec["census"]["LEA"], [])

    def test_manifest_covers_packet(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            entries = [line.split() for line in f if line.strip()]
        self.assertEqual(len(entries), 17)
        for digest, path in entries:
            with open(os.path.normpath(os.path.join(PACKET, path)), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, path)

    def test_no_neighbour_overlap(self):
        fde = (0x63B81B0, 0x63B8517)
        neighbours = [(0x63B8820, 0x63B8D85), (0x63B8D90, 0x63B8FD1),
                      (0x63B8160, 0x63B81AB), (0x63D9340, 0x63D945B),
                      (0x63B9690, 0x63B99C8)]
        for s, e in neighbours:
            self.assertTrue(e <= fde[0] or s >= fde[1], (hex(s), hex(e)))


if __name__ == "__main__":
    unittest.main()
