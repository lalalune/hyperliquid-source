#!/usr/bin/env python3
"""Unit tests for the node #115 lu block register packet
(RE-001-node115-lu-blockreg).

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
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-blockreg")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_blockreg.py")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

EXHIBITS = {
    "cm_anchor": (0x63D94A0, 0x63D94AC, 12, 3),
    "cm_entry": (0x63D94B0, 0x63D94DD, 45, 12),
    "cm_main": (0x63D94DD, 0x63D958B, 174, 40),
    "cm_tail": (0x63D958B, 0x63D95FF, 116, 29),
    "cm_200": (0x63D9600, 0x63D9664, 100, 18),
    "cm_zero": (0x63D9690, 0x63D96C7, 55, 10),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")
JUMP_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t(j\w+)\s+([0-9a-f]+)")
JUMPS = {"ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle",
         "jmp", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge",
         "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo",
         "js", "jz"}


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:", line)]


class BlockRegTests(unittest.TestCase):
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
        self.assertEqual(data[0x63D94B0 - 0x1000:0x63D94B0 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(0x63D96DB - 0x63D94B0, 555)
        self.assertEqual(data[0x63D96DB - 0x1000:0x63D96E0 - 0x1000],
                         b"\xcc" * 5)
        self.assertEqual(data[0x63D95FE - 0x1000], 0xC3)
        self.assertEqual(data[0x63D94A0 - 0x1000:0x63D94A0 - 0x1000 + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(0x63D94AC - 0x63D94A0, 12)
        self.assertEqual(data[0x63D94AB - 0x1000], 0xC3)
        self.assertEqual(data[0x63D94AC - 0x1000:0x63D94B0 - 0x1000],
                         b"\xcc" * 4)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        # Dispatch load: mov 0x68(%rsi),%rax.
        self.assertEqual(data[off(0x63D94C0):off(0x63D94C0) + 4],
                         bytes.fromhex("488b4668"))
        # Flag store: movb $0x1,0x24(%rsi).
        self.assertEqual(data[off(0x63D94C4):off(0x63D94C4) + 4],
                         bytes.fromhex("c6462401"))
        # Size call at 0x63d94e5.
        self.assertEqual(data[off(0x63D94E5)], 0xE8)
        rel = struct.unpack_from("<i", data, off(0x63D94E5) + 1)[0]
        self.assertEqual(0x63D94E5 + 5 + rel, 0x63E8BF0)
        # Handoff calls (not exhibited; verified by rel32).
        for site, tgt in ((0x63D966A, 0x63D8790), (0x63D967F, 0x63D88D0)):
            self.assertEqual(data[off(site)], 0xE8)
            rel = struct.unpack_from("<i", data, off(site) + 1)[0]
            self.assertEqual(site + 5 + rel, tgt)
        # Overflow stub: mov $0x2970,%r11d; jmp 0x63d9548.
        self.assertEqual(data[off(0x63D96D0):off(0x63D96D0) + 6],
                         bytes.fromhex("41bb70290000"))
        self.assertEqual(data[off(0x63D96D6)], 0xE9)
        rel = struct.unpack_from("<i", data, off(0x63D96D6) + 1)[0]
        self.assertEqual(0x63D96D6 + 5 + rel, 0x63D9548)
        # .rodata constant feeding the 0x200 path: qwords 1 and 2.
        self.assertEqual(data[0x450B10:0x450B10 + 16],
                         bytes.fromhex("01000000000000000002000000000000"))

    def test_strict_counts(self):
        for name, (_s, _e, _b, nstrict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                strict = sum(1 for line in f if STRICT_RE.match(line))
            self.assertEqual(strict, nstrict, name)

    def test_tampered_exhibit_rejected(self):
        with open(NODE, "rb") as f:
            data = f.read()
        with open(os.path.join(PACKET, "cm_entry.hex")) as f:
            raw = bytearray(bytes.fromhex("".join(f.read().split())))
        raw[0] ^= 0xFF
        self.assertNotEqual(bytes(raw),
                            data[0x63D94B0 - 0x1000:0x63D94B0 - 0x1000 + 45])

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
                         ["0x63b8c1d", "0x63b8f1a"])
        self.assertEqual(records["census"]["E9"], [])
        self.assertEqual(records["census"]["LEA"], [])
        self.assertEqual(records["census"]["GOT"], [])
        self.assertEqual(records["census"]["rela_dyn_entries"], 60723)

    def test_jump_targets_internal(self):
        text = ""
        for name in EXHIBITS:
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                text += f.read()
        for line in text.splitlines():
            m = JUMP_RE.match(line)
            if m and m.group(1) in JUMPS:
                tgt = int(m.group(2), 16)
                self.assertTrue(0x63D94B0 <= tgt < 0x63D96DB, hex(tgt))
        self.assertEqual(text.count("\tret"), 2)

    def test_census_sites(self):
        with open(NODE, "rb") as f:
            data = f.read()
        off = lambda va: va - 0x1000
        for site in (0x63B8C1D, 0x63B8F1A):
            self.assertEqual(data[off(site)], 0xE8)
            rel = struct.unpack_from("<i", data, off(site) + 1)[0]
            self.assertEqual(site + 5 + rel, 0x63D94B0)


if __name__ == "__main__":
    unittest.main()
