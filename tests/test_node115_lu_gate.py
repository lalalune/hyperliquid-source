#!/usr/bin/env python3
"""Unit tests for the node #115 lu gate packet
(RE-001-node115-lu-gate).

Regeneration comparison + tamper control; no binary execution.
Objdump header lines embed the invoked path, so saved .objdump.txt
files hold instruction lines only and are compared against the same
filtered lines from a fresh objdump run.
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-gate")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_gate.py")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

EXHIBITS = {
    "gt_entry": (0x63B85F0, 0x63B8661, 113, 26),
    "gt_main": (0x63B8667, 0x63B869D, 54, 10),
    "gt_post": (0x63B869D, 0x63B86E6, 73, 12),
    "gt_setup": (0x63B8728, 0x63B874F, 39, 9),
    "gt_drain": (0x63B8790, 0x63B87E3, 83, 15),
    "gt_fail": (0x63B8800, 0x63B881B, 27, 6),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:", line)]


class GateTests(unittest.TestCase):
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
        self.assertEqual(data[0x63B85F0 - 0x1000:0x63B85F0 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(0x63B8820 - 0x63B85F0, 560)
        self.assertEqual(data[0x63B8820 - 0x1000:0x63B8820 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(data[0x63B8709 - 0x1000], 0xC3)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        # Allocator call at 0x63b868c.
        self.assertEqual(data[off(0x63B868C)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B868C) + 1)[0]
        self.assertEqual(0x63B868C + 5 + rel, 0x636B370)
        # Consume call at 0x63b86bc.
        self.assertEqual(data[off(0x63B86BC)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B86BC) + 1)[0]
        self.assertEqual(0x63B86BC + 5 + rel, 0x63BA600)
        # Resolver call at 0x63b873e.
        self.assertEqual(data[off(0x63B873E)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B873E) + 1)[0]
        self.assertEqual(0x63B873E + 5 + rel, 0x63C2130)
        # Flag-clear store at 0x63b865c.
        self.assertEqual(data[off(0x63B865C):off(0x63B865C) + 5],
                         bytes.fromhex("41c6042400"))
        # Flag-set store at 0x63b8800.
        self.assertEqual(data[off(0x63B8800):off(0x63B8800) + 5],
                         bytes.fromhex("41c6042401"))

    def test_strict_counts(self):
        for name, (_s, _e, _b, nstrict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                strict = sum(1 for line in f if STRICT_RE.match(line))
            self.assertEqual(strict, nstrict, name)

    def test_tampered_exhibit_rejected(self):
        with open(NODE, "rb") as f:
            data = f.read()
        with open(os.path.join(PACKET, "gt_main.hex")) as f:
            raw = bytearray(bytes.fromhex("".join(f.read().split())))
        raw[0] ^= 0xFF
        self.assertNotEqual(bytes(raw),
                            data[0x63B8667 - 0x1000:0x63B8667 - 0x1000 + 54])

    def test_verifier_passes(self):
        out = subprocess.run(["python3", VERIFIER],
                             capture_output=True, text=True, check=True)
        self.assertIn("all checks passed", out.stdout)

    def test_records_match(self):
        with open(os.path.join(PACKET, "records.json")) as f:
            records = json.load(f)
        self.assertEqual(records["census"]["E8"],
                         ["0x63b8bdc", "0x63b8ec2"])
        self.assertEqual(records["census"]["E9"], [])
        self.assertEqual(records["census"]["LEA"], [])
        self.assertEqual(records["census"]["GOT"], [])
        self.assertEqual(records["census"]["rela_dyn_entries"], 60723)
        for name, (start, end, nbytes, nstrict) in EXHIBITS.items():
            entry = records["exhibits"][name]
            self.assertEqual(entry["range"],
                             ["0x%x" % start, "0x%x" % end], name)
            self.assertEqual(entry["bytes"], nbytes, name)
            self.assertEqual(entry["strict"], nstrict, name)

    def test_manifest_covers_packet(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            entries = [line.split() for line in f.read().splitlines()
                       if line.strip()]
        self.assertEqual(len(entries), 17)
        names = sorted(path for _digest, path in entries)
        self.assertIn("README.md", names)
        self.assertIn("../../../tools/node115_lu_gate.py", names)
        self.assertIn("../../../tests/test_node115_lu_gate.py", names)

    def test_size_argument_dead(self):
        # The incoming rdx is overwritten before any read: main path
        # writes 0xf8 to edx, setup path writes 0x200000 to edx.
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        self.assertEqual(data[off(0x63B8673):off(0x63B8673) + 5],
                         bytes.fromhex("baf8000000"))
        self.assertEqual(data[off(0x63B872D):off(0x63B872D) + 5],
                         bytes.fromhex("ba00002000"))


if __name__ == "__main__":
    unittest.main()
