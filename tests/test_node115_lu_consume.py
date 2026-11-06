#!/usr/bin/env python3
"""Unit tests for the node #115 lu consume packet
(RE-001-node115-lu-consume).

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
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-consume")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_consume.py")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

EXHIBITS = {
    "cs_entry": (0x63BA600, 0x63BA61E, 30, 6),
    "cs_flags": (0x63BA61E, 0x63BA638, 26, 4),
    "cs_zero": (0x63BA638, 0x63BA672, 58, 10),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:", line)]


class ConsumeTests(unittest.TestCase):
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
        self.assertEqual(data[0x63BA600 - 0x1000:0x63BA600 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(0x63BA672 - 0x63BA600, 114)
        self.assertEqual(data[0x63BA672 - 0x1000:0x63BA680 - 0x1000],
                         b"\xcc" * 14)
        self.assertEqual(data[0x63BA680 - 0x1000:0x63BA680 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(data[0x63BA671 - 0x1000], 0xC3)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        # Cursor store: mov %rsi,(%rdi).
        self.assertEqual(data[off(0x63BA610):off(0x63BA610) + 3],
                         bytes.fromhex("488937"))
        # Counter store: mov %rdx,0x8(%rdi).
        self.assertEqual(data[off(0x63BA613):off(0x63BA613) + 4],
                         bytes.fromhex("48895708"))
        # Header: movl $0x100,0x10(%rdi).
        self.assertEqual(data[off(0x63BA617):off(0x63BA617) + 7],
                         bytes.fromhex("c7471000010000"))
        # Gate main-path consume call at 0x63b86bc.
        self.assertEqual(data[off(0x63B86BC)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B86BC) + 1)[0]
        self.assertEqual(0x63B86BC + 5 + rel, 0x63BA600)
        # Gate drain-path consume call at 0x63b87b9.
        self.assertEqual(data[off(0x63B87B9)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63B87B9) + 1)[0]
        self.assertEqual(0x63B87B9 + 5 + rel, 0x63BA600)
        # .rodata constant feeding [block+0x60]: qword 0x200, qword 0.
        self.assertEqual(data[0x453A60:0x453A60 + 16],
                         bytes.fromhex("00020000000000000000000000000000"))

    def test_strict_counts(self):
        for name, (_s, _e, _b, nstrict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                strict = sum(1 for line in f if STRICT_RE.match(line))
            self.assertEqual(strict, nstrict, name)

    def test_tampered_exhibit_rejected(self):
        with open(NODE, "rb") as f:
            data = f.read()
        with open(os.path.join(PACKET, "cs_entry.hex")) as f:
            raw = bytearray(bytes.fromhex("".join(f.read().split())))
        raw[0] ^= 0xFF
        self.assertNotEqual(bytes(raw),
                            data[0x63BA600 - 0x1000:0x63BA600 - 0x1000 + 30])

    def test_verifier_passes(self):
        out = subprocess.run(["python3", VERIFIER],
                             capture_output=True, text=True, check=True)
        self.assertIn("all checks passed", out.stdout)

    def test_records_match(self):
        with open(os.path.join(PACKET, "records.json")) as f:
            records = json.load(f)
        for name, (start, end, nbytes, nstrict) in EXHIBITS.items():
            rec = records["exhibits"][name]
            self.assertEqual([int(x, 16) for x in rec["range"]],
                             [start, end], name)
            self.assertEqual(rec["bytes"], nbytes, name)
            self.assertEqual(rec["strict"], nstrict, name)
        self.assertEqual(records["census"]["E8"],
                         ["0x63b86bc", "0x63b87b9"])
        self.assertEqual(records["census"]["E9"], [])
        self.assertEqual(records["census"]["LEA"], [])
        self.assertEqual(records["census"]["GOT"], [])
        self.assertEqual(records["census"]["rela_dyn_entries"], 60723)

    def test_no_branch_inside_fde(self):
        text = ""
        for name in EXHIBITS:
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                text += f.read()
        self.assertNotIn("\tcall", text)
        self.assertNotIn("\tjmp", text)
        self.assertEqual(text.count("\tret"), 1)

    def test_untouched_gaps(self):
        # Bytes the helper never writes: +0x18..+0x1f and +0x28..+0x5f.
        # Proven by absence of any store to those offsets in the FDE:
        # the only stores are to +0x00, +0x08, +0x10, +0x14, +0x20,
        # +0x24, +0x60, +0x70..+0xaf, +0xb0, +0xb8..+0xf7.
        text = ""
        for name in EXHIBITS:
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                text += f.read()
        for off in ("0x18(%rdi)", "0x28(%rdi)", "0x30(%rdi)", "0x38(%rdi)",
                    "0x40(%rdi)", "0x48(%rdi)", "0x50(%rdi)", "0x58(%rdi)"):
            self.assertNotIn(off, text, off)


if __name__ == "__main__":
    unittest.main()
