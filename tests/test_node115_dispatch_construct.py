#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-dispatch-construct.

Standalone, no binary execution. Regeneration comparisons strip the
objdump header (which embeds the invoked path) before comparing.
"""

import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research", "work-items", "RE-001-node115-lu-dispatch-construct")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(ROOT, "tools", "node115_dispatch_construct.py")

spec = importlib.util.spec_from_file_location("node115_dispatch_construct",
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
    return subprocess.run(["objdump", "-d"] + args + [BINARY],
                          capture_output=True, text=True,
                          check=True).stdout


class TestDispatchConstruct(unittest.TestCase):
    def test_binary_identity(self):
        data = read_binary()
        self.assertEqual(len(data), 105896032)
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    def test_hex_regeneration(self):
        data = read_binary()
        for name, s, e, _n in V.EXHIBITS:
            with open(os.path.join(PACKET, name + ".hex"), "rb") as f:
                self.assertEqual(f.read(), data[s - 0x1000: e - 0x1000],
                                 name)

    def test_objdump_regeneration(self):
        for name, s, e, _n in V.EXHIBITS:
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                saved = strip_objdump_header(f.read())
            fresh = strip_objdump_header(
                objdump(["--start-address=%s" % hex(s),
                         "--stop-address=%s" % hex(e)]))
            self.assertEqual(saved, fresh, name)

    def test_strict_counts(self):
        for name, _s, _e, n in V.EXHIBITS:
            self.assertEqual(
                V.strict_count(os.path.join(PACKET, name + ".objdump.txt")),
                n, name)

    def test_resolver_entry_targets(self):
        data = read_binary()
        self.assertEqual(V.rel32_target(data, 0x636E36F), 0x63F1AA0)
        self.assertEqual(V.rel32_target(data, 0x636E63F), 0x63BE700)

    def test_sibling_gate(self):
        data = read_binary()
        self.assertEqual(V.rel32_target(data, 0x63A8F37), 0x636E340)
        with open(os.path.join(PACKET, "sibling_gate.objdump.txt")) as f:
            gate = f.read()
        self.assertIn("cmpq   $0x0,0x20(%rsi)", gate)
        self.assertIn("xor    %ecx,%ecx", gate)

    def test_fde6_stats_mutexes(self):
        data = read_binary()
        self.assertEqual(
            V.read_cstr(data, V.lea_target(data, 0x63E83B5)),
            "stats.mutexes")
        self.assertEqual(V.rel32_target(data, 0x63E83C3), 0x63A8D00)
        self.assertEqual(V.rel32_target(data, 0x63E8412), 0x63DC0BB)
        self.assertEqual(V.lea_target(data, 0x63E8441), 0x64FFDC8)

    def test_mutex_table_crosscheck(self):
        data = read_binary()
        rela = V.parse_rela(data)
        got = [V.read_cstr(data, rela[0x64FFD80 + i * 8])
               for i in range(9)]
        self.assertEqual(got, V.MUTEX_TABLE)

    def test_no_hardcoded_index_11(self):
        """No $0xb immediate in the seven dispatcher-caller FDEs,
        and no helper-gate name resolves to the reset leaf.

        Comments are stripped first: objdump '#' suffixes carry
        addresses that must not pollute immediate matching.
        """
        ranges = [(0x63DC0BB, 0x63DC674), (0x63DD1FB, 0x63DE314),
                  (0x63DE5BD, 0x63E1522), (0x63E160A, 0x63E3578),
                  (0x63E3578, 0x63E7DD9), (0x63E7DD9, 0x63E87E5),
                  (0x63E87E5, 0x63E888B)]
        for s, e in ranges:
            out = objdump(["--start-address=%s" % hex(s),
                           "--stop-address=%s" % hex(e)])
            for line in out.splitlines():
                m = re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(.*)$", line)
                if not m:
                    continue
                mnem = m.group(1).split("#")[0]
                for imm in re.findall(r"\$0x([0-9a-f]+)", mnem):
                    self.assertNotEqual(int(imm, 16), 0xB,
                                        "%s in %s" % (mnem, hex(s)))
        with open(os.path.join(PACKET, "records.json")) as f:
            rec = json.load(f)
        sites = rec["census"]["helper_gate_sites"]
        self.assertEqual(len(sites), 110)
        for site in sites:
            name = site["name"]
            self.assertTrue(name, site)
            self.assertNotEqual(name, "reset")
            self.assertNotEqual(name, "mutexes")
            self.assertFalse(name.startswith("stats.mutexes"),
                             name)
            self.assertFalse(name.endswith(".reset"), name)
        self.assertEqual(
            len(rec["census"]["helper_gate_names_distinct"]), 97)
        rsites = rec["census"]["helper_resolve_sites"]
        self.assertEqual(len(rsites), 55)
        for site in rsites:
            name = site["name"]
            self.assertTrue(name, site)
            self.assertNotEqual(name, "reset")
            self.assertNotEqual(name, "mutexes")
            self.assertFalse(name.startswith("stats.mutexes"),
                             name)
            self.assertFalse(name.endswith(".reset"), name)
        self.assertEqual(
            len(rec["census"]["helper_resolve_names_distinct"]), 54)

    def test_verifier_passes(self):
        proc = subprocess.run([sys.executable, VERIFIER],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ALL CHECKS PASSED", proc.stdout)


if __name__ == "__main__":
    unittest.main()
