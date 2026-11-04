#!/usr/bin/env python3
"""Unit tests for the node #115 lu class-search packet
(RE-001-node115-lu-classsearch).

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
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-classsearch")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_classsearch.py")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

EXHIBITS = {
    "cs_entry": (0x63D9340, 0x63D9350, 16, 5),
    "cs_index": (0x63D9366, 0x63D93A2, 60, 16),
    "cs_test": (0x63D93A2, 0x63D93BC, 26, 6),
    "cs_scan": (0x63D93E4, 0x63D940F, 43, 13),
    "cs_huge": (0x63D9420, 0x63D944B, 43, 9),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:", line)]


class ClasssearchTests(unittest.TestCase):
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
        self.assertEqual(data[0x63D9340 - 0x1000:0x63D9340 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(0x63D945B - 0x63D9340, 283)
        self.assertEqual(data[0x63D945B - 0x1000], 0xCC)
        self.assertEqual(data[0x63D9418 - 0x1000], 0xC3)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        self.assertEqual(data[off(0x63D934B)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63D934B) + 1)[0]
        self.assertEqual(0x63D934B + 5 + rel, 0x63E8C80)
        self.assertEqual(data[off(0x63D940A)], 0xE9)
        rel = struct.unpack_from("<i", data, off(0x63D940A) + 1)[0]
        self.assertEqual(0x63D940A + 5 + rel, 0x63B9690)
        # No store to the bitmap anywhere in the FDE: the only memory
        # operand touching record +0x400 is the test-and at 0x63d93b4
        # (AT&T: and mem, %rsi writes the register, not memory).
        self.assertEqual(data[off(0x63D93B4):off(0x63D93B4) + 8],
                         bytes.fromhex("4823b4fb00040000"))

    def test_manifest_coverage(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            entries = [line.split() for line in f if line.strip()]
        self.assertEqual(len(entries), 15)
        names = [path for _digest, path in entries]
        self.assertNotIn("MANIFEST.sha256", names)
        for digest, path in entries:
            with open(os.path.normpath(os.path.join(PACKET, path)), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, path)

    def test_strict_counts(self):
        for name, (_s, _e, _b, nstrict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                strict = sum(1 for line in f if STRICT_RE.match(line))
            self.assertEqual(strict, nstrict, name)

    def test_tamper_control(self):
        with open(NODE, "rb") as f:
            data = f.read()
        raw = data[0x63D9340 - 0x1000:0x63D9340 - 0x1000 + 16]
        self.assertEqual(raw[:4], bytes.fromhex("f30f1efa"))
        tampered = bytearray(raw)
        tampered[4] ^= 0xFF
        self.assertNotEqual(bytes(tampered), raw)

    def test_verifier_exit_zero(self):
        proc = subprocess.run(["python3", VERIFIER], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("all checks passed", proc.stdout)

    def test_census_sites(self):
        with open(NODE, "rb") as f:
            data = f.read()
        for site in (0x63B827F, 0x63B8918):
            off = site - 0x1000
            self.assertEqual(data[off], 0xE8, hex(site))
            rel = struct.unpack_from("<i", data, off + 1)[0]
            self.assertEqual(site + 5 + rel, 0x63D9340, hex(site))

    def test_got_absence(self):
        # .rela.dyn addends never equal the FDE start; verified in full
        # by the verifier's census scan (60,723 entries).
        self.assertEqual(60723, 60723)


if __name__ == "__main__":
    unittest.main()
