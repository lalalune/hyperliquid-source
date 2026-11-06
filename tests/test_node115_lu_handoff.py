#!/usr/bin/env python3
"""Unit tests for the node #115 lu handoff packet
(RE-001-node115-lu-handoff).

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
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-handoff")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_handoff.py")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

EXHIBITS = {
    "hd_entry": (0x63D8790, 0x63D87F8, 104, 33),
    "hd_size": (0x63D8800, 0x63D8879, 121, 30),
    "hd_tail": (0x63D8879, 0x63D88A8, 47, 15),
    "hd_over": (0x63D88B0, 0x63D88C4, 20, 4),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:", line)]


class HandoffTests(unittest.TestCase):
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
        # Entry has no endbr64 (the #233 caution): push %r14, push %r13.
        self.assertEqual(data[0x63D8790 - 0x1000:0x63D8790 - 0x1000 + 4],
                         bytes.fromhex("41564155"))
        self.assertEqual(0x63D88C4 - 0x63D8790, 308)
        self.assertEqual(data[0x63D87F7 - 0x1000], 0xC3)
        self.assertEqual(data[0x63D88C4 - 0x1000:0x63D88D0 - 0x1000],
                         b"\xcc" * 12)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        # Flag store: movb $0x1,0x12(%rsi).
        self.assertEqual(data[off(0x63D87A2):off(0x63D87A2) + 4],
                         bytes.fromhex("c6461201"))
        # Anchor store: mov %rbx,0x1080(%rbp).
        self.assertEqual(data[off(0x63D87E8):off(0x63D87E8) + 7],
                         bytes.fromhex("48899d80100000"))
        # Size-mapping call at 0x63d8810.
        self.assertEqual(data[off(0x63D8810)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63D8810) + 1)[0]
        self.assertEqual(0x63D8810 + 5 + rel, 0x63E8BF0)
        # Entry-probe call at 0x63d8874.
        self.assertEqual(data[off(0x63D8874)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63D8874) + 1)[0]
        self.assertEqual(0x63D8874 + 5 + rel, 0x63B9680)
        # Tail jump at 0x63d88a3.
        self.assertEqual(data[off(0x63D88A3)], 0xE9)
        rel = struct.unpack_from("<i", data, off(0x63D88A3) + 1)[0]
        self.assertEqual(0x63D88A3 + 5 + rel, 0x63B99D0)
        # Census call sites.
        for site in (0x63D9232, 0x63D966A):
            self.assertEqual(data[off(site)], 0xE8)
            rel = struct.unpack_from("<i", data, off(site) + 1)[0]
            self.assertEqual(site + 5 + rel, 0x63D8790)

    def test_strict_counts(self):
        for name, (_s, _e, _b, nstrict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                strict = sum(1 for line in f if STRICT_RE.match(line))
            self.assertEqual(strict, nstrict, name)

    def test_records_match(self):
        with open(os.path.join(PACKET, "records.json")) as f:
            rec = json.load(f)
        for name, (start, end, nbytes, nstrict) in EXHIBITS.items():
            e = rec["exhibits"][name]
            self.assertEqual(e["bytes"], nbytes, name)
            self.assertEqual(e["range"], [hex(start), hex(end)], name)
            self.assertEqual(e["strict"], nstrict, name)
        self.assertEqual(rec["census"]["E8"], ["0x63d9232", "0x63d966a"])
        self.assertEqual(rec["census"]["E9"], [])
        self.assertEqual(rec["census"]["LEA"], [])
        self.assertEqual(rec["census"]["GOT"], [])
        self.assertEqual(rec["census"]["rela_dyn_entries"], 60723)

    def test_tampered_exhibit_rejected(self):
        with open(NODE, "rb") as f:
            data = f.read()
        with open(os.path.join(PACKET, "hd_entry.hex")) as f:
            raw = bytearray(bytes.fromhex("".join(f.read().split())))
        raw[0] ^= 0xFF
        self.assertNotEqual(bytes(raw),
                            data[0x63D8790 - 0x1000:0x63D8790 - 0x1000 + 104])

    def test_manifest_covers_packet(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            entries = [line.split() for line in f if line.strip()]
        self.assertEqual(len(entries), 13)
        for sha, rel in entries:
            p = os.path.normpath(os.path.join(PACKET, rel))
            self.assertTrue(os.path.exists(p), rel)
            with open(p, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), sha, rel)

    def test_verifier_passes(self):
        out = subprocess.run(["python3", VERIFIER],
                             capture_output=True, text=True, check=True)
        self.assertIn("all checks passed", out.stdout)

    def test_no_other_ret_in_fde(self):
        lines = objdump_lines(0x63D8790, 0x63D88C4)
        rets = [line for line in lines if re.search(r"\tret$", line)]
        self.assertEqual(len(rets), 1)
        self.assertIn("63d87f7", rets[0])


if __name__ == "__main__":
    unittest.main()
