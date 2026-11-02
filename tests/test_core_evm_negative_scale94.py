#!/usr/bin/env python3
"""Tests for tools/core_evm_negative_scale94.py (RE-004 negative-decimals scale).

Regeneration tests compare the generator's output byte-for-byte with the
packet and across two runs under different PYTHONHASHSEED/TZ. The model
tests reimplement the ladder walk and the divide grid from the README's
description, independently of the generator's code. Each tamper control flips
one byte of the binary and must make the generator fail; the anchor controls
run with --allow-digest-mismatch so the anchor checks (not the digest check)
are what fail, while the digest control runs without it. One non-anchor
control flips a byte no anchor covers and must still generate (with a
changed window hash), proving the anchors are the enforcement points.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402

TOOL = ROOT / "tools" / "core_evm_negative_scale94.py"
PACKET = ROOT / "research" / "work-items" / "RE-004-core-evm-negative-decimals-scale-94"
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
GENERATED = ["evidence.json", "sites.tsv", "ladder.tsv", "cases.tsv",
             "divide_cases.tsv", "fragment-bytes.txt"]
U64MAX = (1 << 64) - 1


def run_gen(out_dir, binary=None, extra_env=None, allow_digest_mismatch=False):
    cmd = [sys.executable, str(TOOL), "--out", str(out_dir)]
    if binary is not None:
        cmd += ["--binary", str(binary)]
    if allow_digest_mismatch:
        cmd += ["--allow-digest-mismatch"]
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)


def va_to_offset(data, va):
    for section in elf_index.sections(data):
        if section["type"] == 8:
            continue
        start = section["address"]
        if start <= va < start + section["size"]:
            return section["offset"] + (va - start)
    raise AssertionError(f"VA {va:#x} has no file mapping")


def read_tsv(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"))) for line in lines[1:] if line]


class RegenTests(unittest.TestCase):
    def test_regen_matches_packet(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        proc = run_gen(tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in GENERATED:
            self.assertEqual((tmp / name).read_bytes(), (PACKET / name).read_bytes(),
                             f"{name} differs from the packet")

    def test_regen_deterministic(self):
        tmp1 = Path(tempfile.mkdtemp())
        tmp2 = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp1, True)
        self.addCleanup(shutil.rmtree, tmp2, True)
        proc1 = run_gen(tmp1, extra_env={"PYTHONHASHSEED": "1", "TZ": "UTC"})
        proc2 = run_gen(tmp2, extra_env={"PYTHONHASHSEED": "42",
                                          "TZ": "America/New_York"})
        self.assertEqual(proc1.returncode, 0, proc1.stderr)
        self.assertEqual(proc2.returncode, 0, proc2.stderr)
        for name in GENERATED:
            self.assertEqual((tmp1 / name).read_bytes(), (tmp2 / name).read_bytes(),
                             f"{name} is not deterministic")


class ModelTests(unittest.TestCase):
    def test_ladder_model_independent(self):
        """Simulate the bit steps exactly as the README describes them."""
        rows = read_tsv(PACKET / "cases.tsv")
        self.assertEqual(len(rows), 128)
        for row in rows:
            d = int(row["d"])
            al = (-(d & 0xFF)) & 0xFF
            self.assertEqual(al, int(row["al"]))
            # Bit walk with the early exits spelled out per step.
            rcx = 1
            verdict, value = "error", "ladder-bound"
            if al & 1:
                rcx = 10
                if al == 1:
                    verdict, value = "divide", rcx
            if verdict == "error":
                if al & 2:
                    rcx *= 100
                    if (al & ~1) == 2:
                        verdict, value = "divide", rcx
            if verdict == "error":
                if al & 4:
                    rcx *= 10 ** 4
                    if (al & ~3) == 4:
                        verdict, value = "divide", rcx
            if verdict == "error":
                if al & 8:
                    rcx *= 10 ** 8
                    if (al & ~7) == 8:
                        verdict, value = "divide", rcx
            if verdict == "error":
                if al & 16:
                    rcx *= 10 ** 16
                    if (al & 0xF0) == 0x10:
                        if rcx <= U64MAX:
                            verdict, value = "divide", rcx
                        else:
                            verdict, value = "error", "pow10-overflow"
            self.assertEqual(row["verdict"], verdict, f"d={d}")
            if verdict == "divide":
                self.assertEqual(int(row["pow10"]), value, f"d={d}")
            else:
                self.assertEqual(row["reason"], value, f"d={d}")
                self.assertEqual(row["pow10"], "")

    def test_divide_grid_independent(self):
        rows = read_tsv(PACKET / "divide_cases.tsv")
        self.assertEqual(len(rows), 36)
        for row in rows:
            d = int(row["d"])
            pow10 = int(row["pow10"])
            amount = int(row["amount"])
            self.assertEqual(pow10, 10 ** (-d))
            q, r = divmod(amount, pow10)
            self.assertEqual(int(row["quotient"]), q)
            self.assertEqual(int(row["remainder"]), r)
            self.assertEqual(row["exact"] == "True", r == 0)
            path = "div32" if ((amount | pow10) >> 32) == 0 else "div64"
            self.assertEqual(row["path"], path)
            self.assertEqual(row["outcome"],
                             "success-join" if r == 0 else "fallback-0xba")


class TamperTests(unittest.TestCase):
    def tampered_binary(self, va, new_byte):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        data = bytearray(BINARY.read_bytes())
        offset = va_to_offset(bytes(data), va)
        data[offset] = new_byte
        path = tmp / "hl-node-tampered"
        path.write_bytes(bytes(data))
        return path

    def assert_gen_fails(self, binary, allow_digest_mismatch=True):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        proc = run_gen(tmp, binary=binary,
                       allow_digest_mismatch=allow_digest_mismatch)
        self.assertNotEqual(proc.returncode, 0,
                            f"generator unexpectedly passed with {binary}")

    def test_tamper_ladder_immediate(self):
        # copy-1 bit3 imul $0x5f5e100: flip the 0xe1 byte of the immediate.
        binary = self.tampered_binary(0x27156E1 + 4, 0xE2)
        self.assert_gen_fails(binary)

    def test_tamper_decimals_offset(self):
        # copy-1 movzbl 0xd1(%rbx): change the displacement to 0xd2.
        binary = self.tampered_binary(0x271568D + 3, 0xD2)
        self.assert_gen_fails(binary)

    def test_tamper_divide_opcode(self):
        # copy-1 div %rcx: 48 f7 f1 -> 48 f7 f0.
        binary = self.tampered_binary(0x271573B + 2, 0xF0)
        self.assert_gen_fails(binary)

    def test_tamper_flag_offset(self):
        # copy-1 cmpb $0x1, 0xbc(...): change the displacement to 0xbd.
        binary = self.tampered_binary(0x2715641 + 4, 0xBD)
        self.assert_gen_fails(binary)

    def test_tamper_digest(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        data = BINARY.read_bytes()[:-1]
        path = tmp / "hl-node-truncated"
        path.write_bytes(data)
        self.assert_gen_fails(path, allow_digest_mismatch=False)

    def test_non_anchor_change_still_generates(self):
        # copy-1 flag jne displacement: no anchor covers it, so generation
        # must still succeed, but the fragment window hash must change.
        binary = self.tampered_binary(0x271564A + 2, 0xF5)
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        proc = run_gen(tmp, binary=binary, allow_digest_mismatch=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotEqual(
            (tmp / "fragment-bytes.txt").read_bytes(),
            (PACKET / "fragment-bytes.txt").read_bytes())


if __name__ == "__main__":
    unittest.main()
