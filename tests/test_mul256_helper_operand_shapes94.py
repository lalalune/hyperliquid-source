"""Tests for the RE-004 mul256 helper-operand-shapes packet.

Covers regeneration match, cross-env determinism, the independent
operand-selection model (min, shapes, call-2 bound), the anchor tamper
control (a flipped anchor byte fails generation) plus a non-anchor
control (an unanchored byte change still generates), the manifest, and
packet shape. Flag values in cases.tsv are #160 oracle values (grid rows
or runs of #160's own block-level simulation on the exact site shapes);
these tests check the table's internal consistency and shape invariants,
they do not re-derive helper-1's flag logic.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "mul256_helper_operand_shapes94.py"
PACKET = ROOT / "research" / "work-items" / "RE-004-mul256-helper-operand-shapes-94"
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
MASK = (1 << 64) - 1
PRIOR_161_RANGES = [(0x279D201, 0x279D237), (0x279D2B0, 0x279D3B6),
                    (0x279D51F, 0x279D5E0)]


def run_tool(out, binary=None, env_extra=None, extra_args=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    cmd = [sys.executable, str(TOOL), "--out", str(out)]
    if binary is not None:
        cmd += ["--binary", str(binary)]
    cmd += list(extra_args or [])
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)


def parse_limbs(text):
    return tuple(int(x) for x in text.split(","))


def limbs_to_int(limbs):
    v = 0
    for i, x in enumerate(limbs):
        v |= (x & MASK) << (64 * i)
    return v


def read_cases():
    lines = (PACKET / "cases.tsv").read_text().splitlines()
    header = lines[0].split("\t")
    rows = []
    for line in lines[1:]:
        parts = line.split("\t")
        rows.append(dict(zip(header, parts)))
    return rows


class TestRegeneration(unittest.TestCase):
    def test_regeneration_matches_packet(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "regen"
            r = run_tool(out)
            self.assertEqual(r.returncode, 0, r.stderr)
            for name in ("evidence.json", "sites.tsv", "cases.tsv", "windows.txt"):
                self.assertEqual((out / name).read_bytes(),
                                 (PACKET / name).read_bytes(), name)

    def test_cross_env_determinism(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a", Path(d) / "b"
            r1 = run_tool(a, env_extra={"PYTHONHASHSEED": "1", "TZ": "UTC"})
            r2 = run_tool(b, env_extra={"PYTHONHASHSEED": "42", "TZ": "Asia/Seoul"})
            self.assertEqual(r1.returncode, 0, r1.stderr)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            for name in ("evidence.json", "sites.tsv", "cases.tsv", "windows.txt"):
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes(), name)


class TestModel(unittest.TestCase):
    def test_case_shapes_and_products(self):
        rows = read_cases()
        self.assertEqual(len(rows), 15)
        for row in rows:
            if not row["a"]:
                # Panic-path rows carry no operands.
                self.assertEqual(row["helper1_flag"], "")
                continue
            a, b = parse_limbs(row["a"]), parse_limbs(row["b"])
            prod = parse_limbs(row["product"])
            self.assertEqual(limbs_to_int(prod),
                             (limbs_to_int(a) * limbs_to_int(b)) & ((1 << 256) - 1))
            self.assertEqual(row["fits"], "1")
            if row["site"] in ("A1", "B"):
                # a is forced single-limb by the zeroed stack slots.
                self.assertEqual(a[1:], (0, 0, 0))
            if row["site"] == "A2" and row["a"]:
                # a2 has at most two limbs, b2 exactly one.
                self.assertEqual(a[2:], (0, 0))
                self.assertEqual(b[1:], (0, 0, 0))

    def test_flag_collapse_consistency(self):
        # Collapse follows #161's proof: flag 1 -> collapse 1, flag 0 -> 0.
        for row in read_cases():
            if row["helper1_flag"] == "1":
                self.assertEqual(row["collapse_to_zero"], "1", row["case"])
            elif row["helper1_flag"] == "0":
                self.assertEqual(row["collapse_to_zero"], "0", row["case"])

    def test_call2_bound(self):
        # a2 < 2^128 and b2 < 2^64, so every call-2 product is below 2^192
        # and can never truly overflow four limbs.
        for row in read_cases():
            if row["site"] == "A2" and row["a"]:
                a, b = parse_limbs(row["a"]), parse_limbs(row["b"])
                self.assertLess(limbs_to_int(a), 1 << 128)
                self.assertLess(limbs_to_int(b), 1 << 64)
                self.assertLess(limbs_to_int(a) * limbs_to_int(b), 1 << 192)

    def test_b_low_zero_rows_are_the_live_collapse(self):
        # Every A1/B low-zero-b case flags and collapses; no A1/B case
        # with a single-limb b flags.
        for row in read_cases():
            if row["site"] in ("A1", "B") and row["a"]:
                b = parse_limbs(row["b"])
                if b[0] == 0 and any(b[1:]):
                    self.assertEqual(row["helper1_flag"], "1", row["case"])
                elif b[1:] == (0, 0, 0) and b[0] != 0:
                    self.assertEqual(row["helper1_flag"], "0", row["case"])


class TestTamperControls(unittest.TestCase):
    def test_anchor_tamper_fails_generation(self):
        # Flip the caller-A V-load anchor byte at VA 0x279d0d7, located
        # via the section table (the byte pattern alone also occurs in
        # other functions, so a blind pattern search is unreliable).
        sys.path.insert(0, str(ROOT / "tools"))
        import elf_index
        with tempfile.TemporaryDirectory() as d:
            copy = Path(d) / "hl-node"
            shutil.copyfile(BINARY, copy)
            data = copy.read_bytes()
            sections, _ = elf_index.unwind_index(data)
            off = None
            for s in sections:
                if s["type"] == 8:
                    continue
                if s["address"] <= 0x279D0D7 < s["address"] + s["size"]:
                    off = s["offset"] + (0x279D0D7 - s["address"])
            self.assertIsNotNone(off, "VA 0x279d0d7 has no file mapping")
            raw = bytearray(data)
            self.assertEqual(raw[off:off + 7].hex(), "488b8638020000")
            raw[off] ^= 0xFF
            copy.write_bytes(raw)
            out = Path(d) / "regen"
            # Skip the digest gate (the copy is intentionally modified)
            # so the anchor check itself is what must fail.
            r = run_tool(out, binary=copy,
                         extra_args=["--allow-digest-mismatch"])
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("anchor mismatch", r.stderr)

    def test_non_anchor_change_still_generates(self):
        # Flip one padding byte (int3 at VA 0x279d3dc, after caller-A's
        # panic path: inside no claimed window and no anchor) -- the
        # digest gate is skipped and generation must still succeed.
        sys.path.insert(0, str(ROOT / "tools"))
        import elf_index
        with tempfile.TemporaryDirectory() as d:
            copy = Path(d) / "hl-node"
            shutil.copyfile(BINARY, copy)
            data = copy.read_bytes()
            sections, _ = elf_index.unwind_index(data)
            off = None
            for s in sections:
                if s["type"] == 8:
                    continue
                if s["address"] <= 0x279D3DC < s["address"] + s["size"]:
                    off = s["offset"] + (0x279D3DC - s["address"])
            self.assertIsNotNone(off, "VA 0x279d3dc has no file mapping")
            raw = bytearray(data)
            self.assertEqual(raw[off], 0xCC)
            raw[off] ^= 0xFF
            copy.write_bytes(raw)
            out = Path(d) / "regen"
            r = run_tool(out, binary=copy,
                         extra_args=["--allow-digest-mismatch"])
            self.assertEqual(r.returncode, 0, r.stderr)


class TestManifestAndShape(unittest.TestCase):
    def test_manifest(self):
        manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        self.assertEqual(len(manifest), 5)
        for line in manifest:
            digest, name = line.split("  ")
            data = (PACKET / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest, name)

    def test_packet_shape(self):
        for name in ("README.md", "evidence.json", "sites.tsv", "cases.tsv",
                     "windows.txt", "MANIFEST.sha256"):
            self.assertTrue((PACKET / name).is_file(), name)
        evidence = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(evidence["sha256"],
                         "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")
        self.assertEqual(len(evidence["windows"]), 3)
        # Claimed windows sit inside the caller-A/B FDEs but do not
        # overlap #161's anchored ranges.
        for w in evidence["windows"]:
            lo, hi = (int(x, 16) for x in w["range"].split(".."))
            self.assertTrue((0x279D0C0 <= lo and hi <= 0x279D3E0) or
                            (0x279D3E0 <= lo and hi <= 0x279D5E0))
            for ps, pe in PRIOR_161_RANGES:
                self.assertTrue(hi <= ps or lo >= pe, w["label"])
        sites = (PACKET / "sites.tsv").read_text().splitlines()
        self.assertEqual(len(sites), 4)  # header + 3 sites


if __name__ == "__main__":
    unittest.main()
