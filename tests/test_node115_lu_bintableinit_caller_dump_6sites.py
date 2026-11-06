#!/usr/bin/env python3
"""Unit tests for the #278 dump-caller packet verifier.

Tamper controls run FIRST (test_01..test_04) and must each make the
verifier fail; a clean temp copy must pass (test_05); regeneration
and independent recounts follow (test_06..test_09).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLUG = "RE-001-node115-lu-bintableinit-caller-6sites-dump"
PACKET = os.path.join(ROOT, "research", "work-items", SLUG)
VERIFIER = os.path.join(ROOT, "tools",
                        "node115_lu_bintableinit_caller_dump_6sites.py")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
CALL_RE = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\tcall\s+([0-9a-f]+)")
RET_RE = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\tret\s*$")


def make_temp_copy():
    tmp = tempfile.mkdtemp(prefix="hl278-")
    packet_dst = os.path.join(tmp, "research", "work-items", SLUG)
    os.makedirs(packet_dst)
    for name in os.listdir(PACKET):
        shutil.copy2(os.path.join(PACKET, name), os.path.join(packet_dst, name))
    tools_dst = os.path.join(tmp, "tools")
    os.makedirs(tools_dst)
    shutil.copy2(VERIFIER, os.path.join(
        tools_dst, "node115_lu_bintableinit_caller_dump_6sites.py"))
    tests_dst = os.path.join(tmp, "tests")
    os.makedirs(tests_dst)
    shutil.copy2(os.path.abspath(__file__), os.path.join(
        tests_dst, "test_node115_lu_bintableinit_caller_dump_6sites.py"))
    bin_dir = os.path.join(tmp, "artifacts", "node", "115")
    os.makedirs(bin_dir)
    os.symlink(BINARY, os.path.join(bin_dir, "hl-node"))
    return tmp, packet_dst


def run_verifier(root, prior_roots=None):
    env = dict(os.environ)
    env["HL278_ROOT"] = root
    if prior_roots is not None:
        env["HL278_PRIOR_ROOTS"] = prior_roots
    elif "HL278_PRIOR_ROOTS" in env:
        del env["HL278_PRIOR_ROOTS"]
    proc = subprocess.run(
        [sys.executable,
         os.path.join(root, "tools",
                      "node115_lu_bintableinit_caller_dump_6sites.py")],
        env=env, capture_output=True, text=True, timeout=600)
    return proc


class TestPacket278(unittest.TestCase):
    def test_01_tamper_hex_flip(self):
        tmp, packet_dst = make_temp_copy()
        try:
            hex_path = os.path.join(
                packet_dst, "bintableinit_caller_dump_6sites.hex")
            with open(hex_path, "r+b") as fh:
                fh.seek(100)
                fh.write(bytes([fh.read(1)[0] ^ 0xFF]))
            proc = run_verifier(tmp)
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_02_tamper_strict_count(self):
        tmp, packet_dst = make_temp_copy()
        try:
            rec_path = os.path.join(packet_dst, "records.json")
            with open(rec_path) as fh:
                rec = json.load(fh)
            rec["fde"]["strict"] = 453
            with open(rec_path, "w") as fh:
                json.dump(rec, fh)
            proc = run_verifier(tmp)
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_03_tamper_call_site(self):
        tmp, packet_dst = make_temp_copy()
        try:
            obj_path = os.path.join(
                packet_dst, "bintableinit_caller_dump_6sites.objdump.txt")
            with open(obj_path) as fh:
                text = fh.read()
            changed = text.replace("call   63d9880", "call   63d9881", 1)
            self.assertNotEqual(changed, text)
            with open(obj_path, "w") as fh:
                fh.write(changed)
            proc = run_verifier(tmp)
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_04_tamper_injected_overlap(self):
        tmp = tempfile.mkdtemp(prefix="hl278-prior-")
        try:
            fake = os.path.join(tmp, "fake-packet")
            os.makedirs(fake)
            with open(os.path.join(fake, "records.json"), "w") as fh:
                json.dump({"exhibits": [
                    {"name": "overlap",
                     "range": "0x63d4c00..0x63d4d00"}]}, fh)
            proc = run_verifier(ROOT, prior_roots=tmp)
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_05_clean_temp_copy_passes(self):
        tmp, _packet_dst = make_temp_copy()
        try:
            proc = run_verifier(tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_06_regeneration_objdump(self):
        proc = subprocess.run(
            ["objdump", "-d", "--start-address=0x63d4bbe",
             "--stop-address=0x63d5428", BINARY],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        regen = [ln for ln in proc.stdout.splitlines()
                 if re.match(r"^\s*[0-9a-f]+:", ln)]
        with open(os.path.join(
                PACKET, "bintableinit_caller_dump_6sites.objdump.txt")) as fh:
            exhibit = [ln for ln in fh.read().splitlines()
                       if re.match(r"^\s*[0-9a-f]+:", ln)]
        self.assertEqual(regen, exhibit)

    def test_07_regeneration_hex(self):
        with open(BINARY, "rb") as fh:
            fh.seek(0x63D4BBE - 0x1000)
            expect = fh.read(2154)
        with open(os.path.join(
                PACKET, "bintableinit_caller_dump_6sites.hex"), "rb") as fh:
            actual = fh.read()
        self.assertEqual(actual, expect)
        self.assertEqual(len(actual), 2154)

    def test_08_independent_strict_recount(self):
        with open(os.path.join(
                PACKET, "bintableinit_caller_dump_6sites.objdump.txt")) as fh:
            lines = fh.read().splitlines()
        strict = [ln for ln in lines if STRICT_RE.match(ln)]
        self.assertEqual(len(strict), 454)

    def test_09_independent_census(self):
        with open(os.path.join(
                PACKET, "bintableinit_caller_dump_6sites.objdump.txt")) as fh:
            lines = fh.read().splitlines()
        calls = []
        for ln in lines:
            m = CALL_RE.match(ln)
            if m:
                calls.append((int(m.group(1), 16), int(m.group(2), 16)))
        self.assertEqual(len(calls), 69)
        self.assertEqual(sorted(a for a, t in calls if t == 0x63D9880),
                         [0x63D4EED, 0x63D4F2B, 0x63D50AF,
                          0x63D50E7, 0x63D5267, 0x63D529C])
        self.assertEqual([a for a, t in calls if t == 0x63D9700], [])
        rets = [int(m.group(1), 16) for ln in lines
                for m in [RET_RE.match(ln)] if m]
        self.assertEqual(rets, [0x63D5427])


if __name__ == "__main__":
    unittest.main()
