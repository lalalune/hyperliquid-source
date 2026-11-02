#!/usr/bin/env python3
"""Tests for tools/core_evm_scaling_fallback94.py (RE-004 scaling fallback).

Regeneration tests compare the generator's output byte-for-byte with the
packet and across two runs under different PYTHONHASHSEED/TZ. The model
tests reimplement the SSE float sequence and the pow10 chain from the
README's description, independently of the generator's code. Each tamper
control flips one byte of the binary and must make the generator fail;
the anchor controls run with --allow-digest-mismatch so the anchor
checks (not the digest check) are what fail, while the digest control
runs without it. One non-anchor control flips a byte no anchor covers
and must still generate with identical output, proving the anchors are
the enforcement points.
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402

TOOL = ROOT / "tools" / "core_evm_scaling_fallback94.py"
PACKET = ROOT / "research" / "work-items" / "RE-004-core-evm-scaling-fallback-94"
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
GENERATED = ["evidence.json", "sites.tsv", "fallback_cases.tsv",
             "windows.txt"]
WORK = ROOT / "work" / "test-tmp-fallback"
WORK.mkdir(parents=True, exist_ok=True)


def run_gen(out_dir, binary=None, extra_env=None, allow_digest_mismatch=False):
    cmd = [sys.executable, str(TOOL), "--out", str(out_dir)]
    if binary is not None:
        cmd += ["--binary", str(binary)]
    if allow_digest_mismatch:
        cmd += ["--allow-digest-mismatch"]
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(cmd, capture_output=True, text=True, env=env,
                          timeout=300)


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


def double_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def independent_chain():
    """Successive IEEE multiply-by-10 from 1.0, written fresh."""
    chain = [1.0]
    for _ in range(255):
        chain.append(chain[-1] * 10.0)
    return chain


def independent_fallback(amount, byte, table):
    """The SSE sequence from the README, written fresh.

    low = f64(amount mod 2^32); high = 0.0 - 2^84; sum = low + high
    (one IEEE rounding); result = sum / table[byte] (one IEEE rounding).
    """
    low = float(amount & 0xFFFFFFFF)
    high = 0.0 - float(1 << 84)
    summed = low + high
    return summed / table[byte]


class RegenTests(unittest.TestCase):
    def test_regen_matches_packet(self):
        tmp = Path(tempfile.mkdtemp(dir=WORK))
        self.addCleanup(shutil.rmtree, tmp, True)
        proc = run_gen(tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in GENERATED:
            self.assertEqual((tmp / name).read_bytes(),
                             (PACKET / name).read_bytes(),
                             f"{name} differs from the packet")

    def test_regen_deterministic(self):
        tmp1 = Path(tempfile.mkdtemp(dir=WORK))
        tmp2 = Path(tempfile.mkdtemp(dir=WORK))
        self.addCleanup(shutil.rmtree, tmp1, True)
        self.addCleanup(shutil.rmtree, tmp2, True)
        proc1 = run_gen(tmp1, extra_env={"PYTHONHASHSEED": "1", "TZ": "UTC"})
        proc2 = run_gen(tmp2, extra_env={"PYTHONHASHSEED": "42",
                                          "TZ": "America/New_York"})
        self.assertEqual(proc1.returncode, 0, proc1.stderr)
        self.assertEqual(proc2.returncode, 0, proc2.stderr)
        for name in GENERATED:
            self.assertEqual((tmp1 / name).read_bytes(),
                             (tmp2 / name).read_bytes(),
                             f"{name} differs across runs")


class ModelTests(unittest.TestCase):
    def test_case_grid_independent(self):
        rows = read_tsv(PACKET / "fallback_cases.tsv")
        self.assertEqual(len(rows), 56)
        table = independent_chain()
        for row in rows:
            amount = int(row["amount"])
            byte = int(row["byte"])
            value = independent_fallback(amount, byte, table)
            naive = float(amount) / table[byte]
            self.assertEqual(row["table_value"], repr(table[byte]),
                             f"byte={byte}")
            self.assertEqual(int(row["fallback_double_hex"], 16),
                             double_bits(value),
                             f"amount={amount} byte={byte}")
            self.assertEqual(row["fallback_double"], repr(value),
                             f"amount={amount} byte={byte}")
            self.assertEqual(int(row["naive_double_hex"], 16),
                             double_bits(naive),
                             f"amount={amount} byte={byte}")
            self.assertEqual(row["equal"], "1" if value == naive else "0",
                             f"amount={amount} byte={byte}")

    def test_never_equals_naive(self):
        rows = read_tsv(PACKET / "fallback_cases.tsv")
        self.assertTrue(all(row["equal"] == "0" for row in rows))

    def test_chain_vs_rounding_count(self):
        import json
        evidence = json.loads((PACKET / "evidence.json").read_text())
        table_info = evidence["pow10_table"]
        self.assertTrue(table_info["exact_chain"])
        self.assertEqual(table_info["differs_count"], 195)
        self.assertEqual(len(table_info["differs_from_correctly_rounded_pow10"]),
                         195)
        chain = independent_chain()
        for i in table_info["differs_from_correctly_rounded_pow10"]:
            self.assertNotEqual(chain[i], float(10 ** i), f"byte={i}")

    def test_high_half_dropped(self):
        # amount 2^32 has lo32 == 0, so it must equal amount 0 exactly.
        rows = read_tsv(PACKET / "fallback_cases.tsv")
        by_key = {(int(r["amount"]), int(r["byte"])): r for r in rows}
        for byte in (0, 1, 2, 18, 77, 78, 255):
            self.assertEqual(
                by_key[(1 << 32, byte)]["fallback_double_hex"],
                by_key[(0, byte)]["fallback_double_hex"],
                f"byte={byte}")


class TamperTests(unittest.TestCase):
    def setUp(self):
        WORK.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(dir=WORK))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def mutated_binary(self, va, new_byte):
        data = bytearray(BINARY.read_bytes())
        data[va_to_offset(data, va)] = new_byte
        path = self.tmp / "hl-node-mut"
        path.write_bytes(data)
        return path

    def assert_fails(self, va, new_byte, allow_digest_mismatch=True):
        binary = self.mutated_binary(va, new_byte)
        proc = run_gen(self.tmp / "out", binary=binary,
                       allow_digest_mismatch=allow_digest_mismatch)
        self.assertNotEqual(proc.returncode, 0,
                            f"flip at {va:#x} should fail, stderr: {proc.stderr}")

    def test_tamper_bound_cmp(self):
        self.assert_fails(0x271628D + 3, 0x19)

    def test_tamper_movsd(self):
        self.assert_fails(0x27162A8 + 5, 0x59)

    def test_tamper_unpcklps(self):
        self.assert_fails(0x4D0B6B1 + 6, 0x00)

    def test_tamper_subpd(self):
        self.assert_fails(0x4D0CF88 + 7, 0x00)

    def test_tamper_movzx(self):
        self.assert_fails(0x27162BD + 4, 0x4A)

    def test_tamper_lea_table(self):
        self.assert_fails(0x4D0B6D1 + 6, 0x00)

    def test_tamper_divsd(self):
        self.assert_fails(0x4D0CFA8 + 4, 0xC2)

    def test_tamper_tag_ba(self):
        self.assert_fails(0x27162E0 + 2, 0xBB)

    def test_tamper_flag_cmp(self):
        self.assert_fails(0x4D0A9F7 + 8, 0x02)

    def test_tamper_tag_14a(self):
        self.assert_fails(0x4D0C3CC + 2, 0x4B)

    def test_tamper_vcall(self):
        self.assert_fails(0x2716309 + 2, 0x21)

    def test_tamper_double_store(self):
        self.assert_fails(0x4D0B7CF + 6, 0x09)

    def test_tamper_ret(self):
        self.assert_fails(0x4D0D0B7, 0xC2)

    def test_tamper_rem_test(self):
        self.assert_fails(0x2716284 + 2, 0xD3)

    def test_tamper_entry_jmp(self):
        self.assert_fails(0x4D0AD34 + 4, 0x58)

    def test_tamper_panic_lea(self):
        self.assert_fails(0x4D0D606 + 6, 0x01)

    def test_tamper_panic_call(self):
        self.assert_fails(0x271695B + 5, 0x00)

    def test_tamper_table_entry(self):
        self.assert_fails(0x584B08 + 8, 0x01)

    def test_tamper_const_lanes(self):
        self.assert_fails(0x203E80 + 2, 0x31)

    def test_tamper_const_bias(self):
        self.assert_fails(0x202EA0 + 6, 0x31)

    def test_tamper_digest(self):
        # No --allow-digest-mismatch: the digest check itself must fail.
        self.assert_fails(0x2715800, 0x00, allow_digest_mismatch=False)

    def test_non_anchor_control(self):
        # 0x2715800 is in the positive-path loop: no anchor and no
        # transcribed window covers it, so output must be identical.
        binary = self.mutated_binary(0x2715800, 0x00)
        proc = run_gen(self.tmp / "out", binary=binary,
                       allow_digest_mismatch=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in GENERATED:
            self.assertEqual((self.tmp / "out" / name).read_bytes(),
                             (PACKET / name).read_bytes(),
                             f"{name} differs under non-anchor control")


if __name__ == "__main__":
    unittest.main()
