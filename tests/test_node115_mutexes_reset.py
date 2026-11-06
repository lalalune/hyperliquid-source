#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-mutexes-reset.

Standalone, no binary execution. Regeneration comparisons strip the
objdump header (which embeds the invoked path) before comparing.
"""

import hashlib
import importlib.util
import os
import re
import struct
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research", "work-items", "RE-001-node115-lu-mutexes-reset")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(ROOT, "tools", "node115_mutexes_reset.py")

spec = importlib.util.spec_from_file_location("node115_mutexes_reset",
                                              VERIFIER)
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


def read_binary():
    with open(BINARY, "rb") as f:
        return f.read()


def strip_objdump_header(text):
    """Drop everything up to and including the Disassembly/Contents
    header line, since the file header embeds the invoked path."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("Disassembly of section") or \
                line.startswith("Contents of section"):
            return "\n".join(lines[i + 1:])
    return text


def objdump(args):
    return subprocess.run(["objdump"] + args + [BINARY],
                          capture_output=True, text=True,
                          check=True).stdout


class TestMutexesReset(unittest.TestCase):
    def test_binary_identity(self):
        data = read_binary()
        self.assertEqual(len(data), 105896032)
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    def test_hex_regeneration(self):
        data = read_binary()
        with open(os.path.join(PACKET, "dispatcher.hex"), "rb") as f:
            saved = f.read()
        self.assertEqual(
            saved, data[0x63A8FF0 - 0x1000: 0x63A93BA - 0x1000])
        self.assertEqual(len(saved), 970)
        for name, va in [("node_root", 0x64DA4C0),
                         ("node_stats", 0x64DA6B8),
                         ("node_mutexes", 0x64DABE0),
                         ("node_reset", 0x64DADC8)]:
            with open(os.path.join(PACKET, name + ".hex"), "rb") as f:
                saved = f.read()
            self.assertEqual(saved, data[va - 0x2000: va - 0x2000 + 40],
                             name)

    def test_objdump_regeneration(self):
        fresh = objdump(["-d", "--start-address=0x63a8ff0",
                         "--stop-address=0x63a93ba"])
        with open(os.path.join(PACKET,
                               "dispatcher.objdump.txt")) as f:
            saved = f.read()
        self.assertEqual(strip_objdump_header(fresh),
                         strip_objdump_header(saved))
        for name, va in [("node_root", 0x64DA4C0),
                         ("node_stats", 0x64DA6B8),
                         ("node_mutexes", 0x64DABE0),
                         ("node_reset", 0x64DADC8)]:
            fresh = objdump(["-s", "--start-address=%#x" % va,
                             "--stop-address=%#x" % (va + 0x28)])
            with open(os.path.join(PACKET,
                                   name + ".objdump.txt")) as f:
                saved = f.read()
            self.assertEqual(strip_objdump_header(fresh),
                             strip_objdump_header(saved), name)

    def test_strict_count(self):
        self.assertEqual(
            V.strict_count(os.path.join(PACKET, "dispatcher.objdump.txt")),
            232)

    def test_index_arithmetic(self):
        self.assertEqual(0x64DA500 + 11 * 0x28, 0x64DA6B8)
        self.assertEqual(0x64DAAA0 + 8 * 0x28, 0x64DABE0)
        self.assertEqual(0x64DAC60 + 9 * 0x28, 0x64DADC8)

    def test_sweep_single_inbound(self):
        data = read_binary()
        rela = V.parse_rela(data)
        self.assertEqual([o for o, a in rela.items()
                          if a == 0x63A5BF0], [0x64DADE8])
        # The handler slot is the reset leaf's +0x20 field.
        self.assertEqual(
            V.runtime_value(data, rela, 0x64DADC8 + 0x20), 0x63A5BF0)

    def test_dispatcher_census(self):
        data = read_binary()
        base_va, base_off = 0x1419300, 0x1418300
        text = data[base_off: base_off + 0x4FD7700]
        e8, e9 = set(), set()
        for i in range(len(text) - 5):
            op = text[i]
            if op not in (0xE8, 0xE9):
                continue
            rel = struct.unpack("<i", text[i + 1: i + 5])[0]
            if base_va + i + 5 + rel == 0x63A8FF0:
                (e8 if op == 0xE8 else e9).add(base_va + i)
        self.assertEqual(e8, V.EXPECT_E8)
        self.assertEqual(len(e9), 0)

    def test_tamper_control(self):
        data = read_binary()
        good = data[0x63A8FF0 - 0x1000: 0x63A93BA - 0x1000]
        bad = bytearray(good)
        bad[10] ^= 0xFF
        with open(os.path.join(PACKET, "dispatcher.hex"), "rb") as f:
            saved = f.read()
        self.assertEqual(saved, good)
        self.assertNotEqual(bytes(bad), saved)
        # A flipped node field breaks the runtime-field check.
        rela = V.parse_rela(data)
        fields = [V.runtime_value(data, rela, 0x64DADC8 + k * 8)
                  for k in range(5)]
        tampered = list(fields)
        tampered[4] = 0x63A5BF1
        self.assertNotEqual(tampered, fields)

    def test_disjointness(self):
        claimed = V.collect_claimed(ROOT)
        overlaps = [(a, b) for (a, b) in claimed
                    if any(x < b and a < y for x, y in V.MY_RANGES)]
        self.assertEqual(overlaps, [])

    def test_verifier_exit_zero(self):
        proc = subprocess.run([sys.executable, VERIFIER],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ALL CHECKS PASSED", proc.stdout)


if __name__ == "__main__":
    unittest.main()
