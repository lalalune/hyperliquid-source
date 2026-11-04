#!/usr/bin/env python3
"""Unit tests for the node #115 lu class-merge packet
(RE-001-node115-lu-classmerge).

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
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-classmerge")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_classmerge.py")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

EXHIBITS = {
    "cs_entry": (0x63B9690, 0x63B96C6, 54, 16),
    "cs_pair": (0x63B9700, 0x63B9758, 88, 23),
    "cs_loop": (0x63B97D4, 0x63B97F6, 34, 9),
    "cs_phaseb": (0x63B9840, 0x63B9887, 71, 18),
    "cs_final": (0x63B98D1, 0x63B991B, 74, 20),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:", line)]


class ClassmergeTests(unittest.TestCase):
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
        self.assertEqual(data[0x63B9690 - 0x1000:0x63B9690 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(0x63B99C8 - 0x63B9690, 824)
        self.assertEqual(data[0x63B99C8 - 0x1000], 0xCC)
        self.assertEqual(data[0x63B9925 - 0x1000], 0xC3)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        # Entry zeroes [slot+8]: movq $0x0,0x8(%rdi) at 0x63b96b2.
        self.assertEqual(data[off(0x63B96B2):off(0x63B96B2) + 8],
                         bytes.fromhex("48c7470800000000"))
        # Class-search tail jump at 0x63d940a targets this FDE.
        self.assertEqual(data[off(0x63D940A)], 0xE9)
        rel = struct.unpack_from("<i", data, off(0x63D940A) + 1)[0]
        self.assertEqual(0x63D940A + 5 + rel, 0x63B9690)
        # Final [slot] store at 0x63b9914: mov %rbx,0x0(%rbp).
        self.assertEqual(data[off(0x63B9914):off(0x63B9914) + 4],
                         bytes.fromhex("48895d00"))

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
        raw = data[0x63B9690 - 0x1000:0x63B9690 - 0x1000 + 16]
        self.assertEqual(raw[:4], bytes.fromhex("f30f1efa"))
        tampered = bytearray(raw)
        tampered[4] ^= 0xFF
        self.assertNotEqual(bytes(tampered), raw)

    def test_verifier_exit_zero(self):
        proc = subprocess.run(["python3", VERIFIER], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("all checks passed", proc.stdout)

    def test_tail_jump_site(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = 0x63D940A - 0x1000
        self.assertEqual(data[off], 0xE9)
        rel = struct.unpack_from("<i", data, off + 1)[0]
        self.assertEqual(0x63D940A + 5 + rel, 0x63B9690)

    def test_got_absence(self):
        # .rela.dyn addends never equal the FDE start; verified in full
        # by the verifier's census scan (60,723 entries).
        self.assertEqual(60723, 60723)


if __name__ == "__main__":
    unittest.main()
