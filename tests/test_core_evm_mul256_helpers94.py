#!/usr/bin/env python3
"""Tests for tools/core_evm_mul256_helpers94.py (RE-004 mul256 helpers).

Regeneration tests compare the generator's output byte-for-byte with the
packet and across two runs under different PYTHONHASHSEED/TZ. The model
tests reimplement the flag rules from the README's description,
independently of the generator's block-level simulations: helper-2's
flag equals true overflow, helper-1's flag equals (the r11<r12 flag path
fires) OR (true overflow), and helper-2's out equals the 256-bit sum of
the caller's out buffer and the product. Each tamper control flips one
byte of the binary and must make the generator fail; the anchor
controls run with --allow-digest-mismatch so the anchor checks (not the
digest check) are what fail, while the digest control runs without it.
One non-anchor control flips a byte no anchor covers and must still
generate with identical output, proving the anchors are the enforcement
points.
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

TOOL = ROOT / "tools" / "core_evm_mul256_helpers94.py"
PACKET = ROOT / "research" / "work-items" / "RE-004-core-evm-mul256-helpers-94"
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
GENERATED = ["evidence.json", "sites.tsv", "loop_cases.tsv", "windows.txt"]
WORK = ROOT / "work" / "test-tmp-mul256"
WORK.mkdir(parents=True, exist_ok=True)
M64 = (1 << 64) - 1


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


def limbs(text):
    return [int(v) for v in text.split(",")] if text else []


def as_int(limbs_list):
    return sum(v << (64 * i) for i, v in enumerate(limbs_list))


def as_limbs(value):
    return [(value >> (64 * i)) & M64 for i in range(4)]


def independent_helper1_flag(a, b):
    """Helper-1 flag from the README's rule, written fresh.

    a_skip / b_skip are leading zero limbs; a_count = 4 - a_skip;
    b_sig is the significant count of trimmed b; outer_count is the
    smaller count; r12 is the larger count; r11 starts at
    a_count - b_skip and decrements per outer iteration, so the flag
    path fires iff r11 drops below r12 before the loop ends. The
    carry path fires exactly on true overflow when the flag path does
    not, and a == 0 short-circuits to flag 0.
    """
    if all(v == 0 for v in a):
        return 0
    a_skip = 0
    while a_skip < 4 and a[a_skip] == 0:
        a_skip += 1
    b_skip = 0
    while b_skip < 4 and b[b_skip] == 0:
        b_skip += 1
    if b_skip == 4:
        # b == 0: r11 == 0 entry iff a has no low skip
        return 1 if a_skip == 0 else None  # None = out of scope
    if a_skip + b_skip > 4:
        return None  # out of scope (r11 wraps)
    a_count = 4 - a_skip
    trimmed_b = b[b_skip:]
    b_sig = 0
    for i, v in enumerate(trimmed_b):
        if v != 0:
            b_sig = i + 1
    r12 = max(a_count, b_sig)
    outer_count = min(a_count, b_sig)
    r11_init = a_count - b_skip
    flag_path = (r11_init - (outer_count - 1)) < r12
    true_overflow = 1 if as_int(a) * as_int(b) >= (1 << 256) else 0
    return 1 if (flag_path or true_overflow) else 0


class TestRegeneration(unittest.TestCase):
    def test_matches_packet(self):
        tmp = Path(tempfile.mkdtemp(dir=WORK))
        result = run_gen(tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in GENERATED:
            self.assertEqual((tmp / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_deterministic_across_env(self):
        tmp1 = Path(tempfile.mkdtemp(dir=WORK))
        tmp2 = Path(tempfile.mkdtemp(dir=WORK))
        r1 = run_gen(tmp1, extra_env={"PYTHONHASHSEED": "1", "TZ": "UTC"})
        r2 = run_gen(tmp2, extra_env={"PYTHONHASHSEED": "42", "TZ": "Asia/Seoul"})
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        for name in GENERATED:
            self.assertEqual((tmp1 / name).read_bytes(),
                             (tmp2 / name).read_bytes(), name)


class TestModels(unittest.TestCase):
    def test_case_table(self):
        rows = read_tsv(PACKET / "loop_cases.tsv")
        self.assertEqual(len(rows), 21)
        h1_exact = h2_exact = agree = 0
        for row in rows:
            a, b = limbs(row["a"]), limbs(row["b"])
            out_init = limbs(row["out_init"])
            closed_val = as_limbs(as_int(a) * as_int(b) % (1 << 256))
            closed_flag = 1 if as_int(a) * as_int(b) >= (1 << 256) else 0
            self.assertEqual(limbs(row["closed_value"]), closed_val, row["case"])
            self.assertEqual(int(row["closed_overflow"]), closed_flag, row["case"])
            # helper-1 value always equals the closed-form product
            self.assertEqual(limbs(row["helper1_value"]), closed_val, row["case"])
            # helper-2 value equals out_init + product (256-bit addition)
            expect_h2 = as_limbs((as_int(out_init) + as_int(closed_val)) % (1 << 256))
            self.assertEqual(limbs(row["helper2_value"]), expect_h2, row["case"])
            # helper-2 flag is exact overflow
            self.assertEqual(int(row["helper2_flag"]), closed_flag, row["case"])
            # helper-1 flag follows the independent rule
            want_h1 = independent_helper1_flag(a, b)
            self.assertIsNotNone(want_h1, row["case"])
            self.assertEqual(int(row["helper1_flag"]), want_h1, row["case"])
            h1_exact += int(row["helper1_flag"]) == closed_flag
            h2_exact += int(row["helper2_flag"]) == closed_flag
            agree += int(row["helper1_flag"]) == int(row["helper2_flag"])
        self.assertEqual(h1_exact, 11)
        self.assertEqual(h2_exact, 21)
        self.assertEqual(agree, 11)

    def test_sites_and_windows(self):
        sites = read_tsv(PACKET / "sites.tsv")
        self.assertEqual(len(sites), 14)
        self.assertEqual(sum(1 for s in sites if s["helper"] == "helper-1"), 6)
        self.assertEqual(sum(1 for s in sites if s["helper"] == "helper-2"), 8)
        self.assertEqual(sum(1 for s in sites if s["role"] == "scaling"), 9)
        self.assertEqual(sum(1 for s in sites if s["role"] == "other"), 5)
        windows = (PACKET / "windows.txt").read_text().splitlines()
        self.assertEqual(len(windows), 4)
        for line in windows:
            label, span, blob = line.split(" ")
            start, end = span.split("..")
            self.assertEqual((int(end, 16) - int(start, 16)) * 2, len(blob), label)

    def test_evidence_counts(self):
        import json
        evidence = json.loads((PACKET / "evidence.json").read_text())
        counts = evidence["case_counts"]
        self.assertEqual(counts["cases"], 21)
        self.assertEqual(counts["helper1_value_ok"], 21)
        self.assertEqual(counts["helper2_value_ok"], 19)
        self.assertEqual(counts["helper1_flag_exact"], 11)
        self.assertEqual(counts["helper2_flag_exact"], 21)
        self.assertEqual(counts["flags_agree"], 11)
        self.assertEqual(evidence["helpers"]["helper-1"]["sha256"],
                         "7f75ff37b1ecfcf33aade0a848fa4f4c9389a1504dd3981625510c8311379801")
        self.assertEqual(evidence["helpers"]["helper-2"]["sha256"],
                         "189ebebb967715ee4bdec2501a1df85621c602d73466dc56d6f230cadbdef472")


class TestTamper(unittest.TestCase):
    def tampered_binary(self, va):
        data = bytearray(BINARY.read_bytes())
        off = va_to_offset(bytes(data), va)
        data[off] ^= 0xFF
        tmp = Path(tempfile.mkdtemp(dir=WORK)) / "hl-node"
        tmp.write_bytes(bytes(data))
        return tmp

    def assert_fails(self, binary, allow_digest_mismatch):
        tmp = Path(tempfile.mkdtemp(dir=WORK))
        result = run_gen(tmp, binary=binary,
                         allow_digest_mismatch=allow_digest_mismatch)
        self.assertNotEqual(result.returncode, 0)

    def test_digest_control(self):
        # No --allow-digest-mismatch: any byte flip must fail at the digest.
        self.assert_fails(self.tampered_binary(0x27A1400), False)

    def test_anchor_controls(self):
        # One byte per anchor class, with --allow-digest-mismatch so the
        # anchor check (not the digest) is what must fail.
        for va in (0x27A1150, 0x27A1161, 0x27A138F, 0x27A13B9, 0x27A1400,
                   0x27A14D0, 0x27A151B, 0x27A145E, 0x27A146A, 0x27A156E,
                   0x27A1537, 0x27A1547, 0x4DE5500, 0x4DE550E, 0x4DE5720,
                   0x4DE574A, 0x4DE57A0, 0x4DE5870, 0x4DE58BA, 0x4DE57FE,
                   0x4DE580B, 0x4DE55FD, 0x4DE58D6, 0x4DE58E6, 0x4D0ABD6):
            with self.subTest(va=hex(va)):
                self.assert_fails(self.tampered_binary(va), True)

    def test_non_anchor_control(self):
        # A byte no anchor covers (the int3 pad byte at 0x27a162f, just
        # past helper-1's readelf FDE end) must still generate. The
        # pad byte is inside the transcribed trilogy window, so
        # windows.txt and the window hash in evidence.json legitimately
        # change; the anchor-independent outputs must be identical.
        tmp = Path(tempfile.mkdtemp(dir=WORK))
        result = run_gen(tmp, binary=self.tampered_binary(0x27A162F),
                         allow_digest_mismatch=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("sites.tsv", "loop_cases.tsv"):
            self.assertEqual((tmp / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_relocation_control(self):
        # Flipping the R_X86_64_RELATIVE addend for GOT 0x576e2e0 must
        # fail the relocation check (with --allow-digest-mismatch so
        # the relocation check, not the digest, is what fails).
        data = bytearray(BINARY.read_bytes())
        raw = bytes(data)  # hoisted: never copy the 90 MB binary in a loop
        sections = elf_index.sections(raw)
        rela = next(s for s in sections if s["name"] == ".rela.dyn")
        target_off = None
        for i in range(rela["size"] // 24):
            off, info, add = struct.unpack_from("<QQq", raw,
                                                rela["offset"] + i * 24)
            if off == 0x576E2E0:
                target_off = rela["offset"] + i * 24 + 16
                break
        self.assertIsNotNone(target_off)
        data[target_off] ^= 0xFF
        tmp = Path(tempfile.mkdtemp(dir=WORK)) / "hl-node"
        tmp.write_bytes(bytes(data))
        self.assert_fails(tmp, True)


if __name__ == "__main__":
    unittest.main()
