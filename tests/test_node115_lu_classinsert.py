#!/usr/bin/env python3
"""Unit tests for the node #115 lu class-insert packet
(RE-001-node115-lu-classinsert).

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
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-classinsert")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_classinsert.py")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

EXHIBITS = {
    "tl_entry": (0x63B99D0, 0x63B99F5, 37, 11),
    "tl_cmp": (0x63B99F5, 0x63B9A1E, 41, 11),
    "tl_insert": (0x63B9A1E, 0x63B9A4D, 47, 16),
    "tl_min": (0x63B9CC0, 0x63B9CD8, 24, 8),
    "tl_loop": (0x63B9A50, 0x63B9A7A, 42, 12),
    "tl_step": (0x63B9B10, 0x63B9B8A, 122, 30),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:", line)]


class ClassInsertTests(unittest.TestCase):
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
        self.assertEqual(data[0x63B99D0 - 0x1000:0x63B99D0 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(0x63B9D0C - 0x63B99D0, 828)
        self.assertEqual(data[0x63B9A4C - 0x1000], 0xC3)
        self.assertEqual(data[0x63B9CD7 - 0x1000], 0xC3)
        self.assertEqual(data[0x63B99C8 - 0x1000:0x63B99D0 - 0x1000],
                         b"\xcc" * 8)
        self.assertEqual(data[0x63B9D0C - 0x1000:0x63B9D10 - 0x1000],
                         b"\xcc" * 4)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        # Block +0x28/+0x30 zeroed, +0x38 zeroed.
        self.assertEqual(data[off(0x63B99E3):off(0x63B99E3) + 4],
                         bytes.fromhex("0f114628"))
        self.assertEqual(data[off(0x63B99EA):off(0x63B99EA) + 8],
                         bytes.fromhex("48c7411000000000"))
        # Count bump: [entry+8] += 1.
        self.assertEqual(data[off(0x63B9A1E):off(0x63B9A1E) + 4],
                         bytes.fromhex("488b5f08"))
        self.assertEqual(data[off(0x63B9A26):off(0x63B9A26) + 4],
                         bytes.fromhex("48896f08"))
        # tzcnt on count-1.
        self.assertEqual(data[off(0x63B9A57):off(0x63B9A57) + 5],
                         bytes.fromhex("f34c0fbcdd"))
        # Min displacement: [block+0x38] := head, [entry+8] := 0.
        self.assertEqual(data[off(0x63B9CC0):off(0x63B9CC0) + 4],
                         bytes.fromhex("48897110"))
        self.assertEqual(data[off(0x63B9CCB):off(0x63B9CCB) + 8],
                         bytes.fromhex("48c7470800000000"))
        # Tail jump from the handoff's size path.
        self.assertEqual(data[off(0x63D88A3)], 0xE9)
        rel = struct.unpack_from("<i", data, off(0x63D88A3) + 1)[0]
        self.assertEqual(0x63D88A3 + 5 + rel, 0x63B99D0)

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
        self.assertEqual(rec["census"]["E8"], [])
        self.assertEqual(rec["census"]["E9"], ["0x63d88a3"])
        self.assertEqual(rec["census"]["LEA"], [])
        self.assertEqual(rec["census"]["GOT"], [])
        self.assertEqual(rec["census"]["rela_dyn_entries"], 60723)

    def test_tampered_exhibit_rejected(self):
        with open(NODE, "rb") as f:
            data = f.read()
        with open(os.path.join(PACKET, "tl_entry.hex")) as f:
            raw = bytearray(bytes.fromhex("".join(f.read().split())))
        raw[0] ^= 0xFF
        self.assertNotEqual(bytes(raw),
                            data[0x63B99D0 - 0x1000:0x63B99D0 - 0x1000 + 37])

    def test_manifest_covers_packet(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            entries = [line.split() for line in f if line.strip()]
        self.assertEqual(len(entries), 17)
        for sha, rel in entries:
            p = os.path.normpath(os.path.join(PACKET, rel))
            self.assertTrue(os.path.exists(p), rel)
            with open(p, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), sha, rel)

    def test_verifier_passes(self):
        out = subprocess.run(["python3", VERIFIER],
                             capture_output=True, text=True, check=True)
        self.assertIn("all checks passed", out.stdout)

    def test_rets_and_no_calls_in_fde(self):
        lines = objdump_lines(0x63B99D0, 0x63B9D0C)
        rets = [line for line in lines if re.search(r"\tret$", line)]
        self.assertEqual(len(rets), 2)
        self.assertTrue(any("63b9a4c" in line for line in rets))
        self.assertTrue(any("63b9cd7" in line for line in rets))
        calls = [line for line in lines if re.search(r"\tcall\s", line)]
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
