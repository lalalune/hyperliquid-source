#!/usr/bin/env python3
"""Tests for tools/core_evm_positive_scale94.py (RE-004 positive-decimals scale).

Regeneration tests compare the generator's output byte-for-byte with the
packet and across two runs under different PYTHONHASHSEED/TZ. The model
tests reimplement the square-and-multiply loop and the final multiply grid
from the README's description, independently of the generator's code. Each
tamper control flips one byte of the binary and must make the generator
fail; the anchor controls run with --allow-digest-mismatch so the anchor
checks (not the digest check) are what fail, while the digest control runs
without it. One non-anchor control flips a byte no anchor covers and must
still generate with identical output, proving the anchors are the
enforcement points.
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

TOOL = ROOT / "tools" / "core_evm_positive_scale94.py"
PACKET = ROOT / "research" / "work-items" / "RE-004-core-evm-positive-decimals-scale-94"
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
GENERATED = ["evidence.json", "sites.tsv", "loop_cases.tsv",
             "final_cases.tsv", "windows.txt"]
U256 = 1 << 256
WORK = ROOT / "work" / "test-tmp-positive"
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


def independent_loop(d):
    """Square-and-multiply from the README description, written fresh.

    acc starts at 1, base at 10. While d remains: on a set bit, acc is
    replaced by the low 256 bits of acc*base and the loop flag becomes 1
    if any of the old flag, this multiply's overflow, or any earlier
    square overflow is set; then base is squared (its overflow joins the
    square accumulator, which is only folded at a later set-bit step).
    """
    acc, base, flag, sq, rest = 1, 10, 0, 0, d
    while rest:
        if rest & 1:
            prod = acc * base
            flag = 1 if (flag or prod >= U256 or sq) else 0
            acc = prod % U256
        prod = base * base
        sq = sq or (prod >= U256)
        base = prod % U256
        rest >>= 1
    return acc, flag


class RegenTests(unittest.TestCase):
    def test_regen_matches_packet(self):
        tmp = Path(tempfile.mkdtemp(dir=WORK))
        self.addCleanup(shutil.rmtree, tmp, True)
        proc = run_gen(tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in GENERATED:
            self.assertEqual((tmp / name).read_bytes(), (PACKET / name).read_bytes(),
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
            self.assertEqual((tmp1 / name).read_bytes(), (tmp2 / name).read_bytes(),
                             f"{name} differs across runs")


class ModelTests(unittest.TestCase):
    def test_loop_model_independent(self):
        rows = read_tsv(PACKET / "loop_cases.tsv")
        self.assertEqual(len(rows), 256)
        for row in rows:
            d = int(row["d"])
            pow10, overflow = independent_loop(d)
            self.assertEqual(int(row["loop_overflow"]), overflow, f"d={d}")
            self.assertEqual(row["outcome"], "fallback" if overflow else "success",
                             f"d={d}")
            if overflow:
                self.assertEqual(row["pow10_hex"], "", f"d={d}")
            else:
                self.assertEqual(int(row["pow10_hex"], 16), pow10, f"d={d}")
                self.assertEqual(int(row["pow10_dec"]), pow10, f"d={d}")

    def test_loop_boundary(self):
        # 10^77 < 2^256 < 10^78, so 77 is the largest exact exponent.
        self.assertLess(10 ** 77, U256)
        self.assertGreaterEqual(10 ** 78, U256)
        for d in range(78):
            _, overflow = independent_loop(d)
            self.assertEqual(overflow, 0, f"d={d} should not overflow")
        for d in range(78, 256):
            _, overflow = independent_loop(d)
            self.assertEqual(overflow, 1, f"d={d} should overflow")

    def test_final_square_overflow_dropped(self):
        # d in 64..77: the last iteration squares 10^64 to 10^128, which
        # overflows, but the loop exits right after, so the square flag is
        # never folded and the loop still succeeds with the exact pow10.
        for d in range(64, 78):
            pow10, overflow = independent_loop(d)
            self.assertEqual(overflow, 0, f"d={d}")
            self.assertEqual(pow10, 10 ** d, f"d={d}")

    def test_final_grid_independent(self):
        rows = read_tsv(PACKET / "final_cases.tsv")
        by_key = {(int(r["d"]), r["amount"]): r for r in rows if r["amount"]}
        for d in (0, 1, 18, 19, 77):
            pow10, overflow = independent_loop(d)
            self.assertEqual(overflow, 0)
            threshold = (U256 + pow10 - 1) // pow10
            for amount in (0, 1, 2, (1 << 64) - 1, threshold - 1, threshold):
                row = by_key[(d, str(amount))]
                prod = (amount * pow10) % U256
                ov = 1 if amount * pow10 >= U256 else 0
                self.assertEqual(int(row["product"]), prod, f"d={d} amount={amount}")
                self.assertEqual(int(row["final_overflow"]), ov, f"d={d} amount={amount}")
                self.assertEqual(row["outcome"], "fallback" if ov else "success")

    def test_admitted_range_never_overflows(self):
        # Through legitimate records d is in 0..18 and the amount is a u64;
        # (2^64 - 1) * 10^18 is far below 2^256, so the final multiply
        # cannot overflow there.
        for d in range(19):
            pow10, _ = independent_loop(d)
            self.assertLess(((1 << 64) - 1) * pow10, U256, f"d={d}")


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

    def test_tamper_base10(self):
        self.assert_fails(0x271576F + 11, 0x0B)

    def test_tamper_movzx(self):
        self.assert_fails(0x4D0AB31 + 3, 0xFB)

    def test_tamper_acc_call(self):
        self.assert_fails(0x2715834 + 4, 0x18)

    def test_tamper_acc_fold(self):
        self.assert_fails(0x4D0AC24 + 10, 0x00)

    def test_tamper_sq_call(self):
        self.assert_fails(0x4D0C548 + 4, 0xB4)

    def test_tamper_sq_fold(self):
        self.assert_fails(0x27158BB + 7, 0x51)

    def test_tamper_exit_jmp(self):
        self.assert_fails(0x4D0C604 + 4, 0x58)

    def test_tamper_shortcut_constant(self):
        self.assert_fails(0x20A720, 0x02)

    def test_tamper_helper_overflow_store(self):
        self.assert_fails(0x27A12ED + 2, 0x21)

    def test_tamper_helper2_overflow_one(self):
        self.assert_fails(0x4DE55A3 + 1, 0x00)

    def test_tamper_digest(self):
        # No --allow-digest-mismatch: any byte flip must fail at the digest.
        self.assert_fails(0x2716000, 0x00, allow_digest_mismatch=False)

    def test_non_anchor_change_still_generates(self):
        # 0x2716000 is inside handler copy-1 but outside every transcribed
        # window and every anchor, so generation must succeed identically.
        binary = self.mutated_binary(0x2716000, 0x00)
        proc = run_gen(self.tmp / "out", binary=binary,
                       allow_digest_mismatch=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in GENERATED:
            self.assertEqual((self.tmp / "out" / name).read_bytes(),
                             (PACKET / name).read_bytes(),
                             f"{name} differs on a non-anchor change")


if __name__ == "__main__":
    unittest.main()
