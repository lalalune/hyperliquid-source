"""Tests for the RE-004 mul256 non-scaling flag-use packet.

Regeneration, cross-env determinism, an independent big-integer model of
the caller outcomes, anchor/digest tamper controls, and packet shape.
"""

import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-004-mul256-non-scaling-flag-use-94"
TOOL = ROOT / "tools" / "mul256_non_scaling_flag_use94.py"
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
MASK = (1 << 64) - 1
MOD = 1 << 256

GENERATED = ["evidence.json", "sites.tsv", "cases.tsv", "windows.txt"]


def run_tool(out, binary=None, allow_mismatch=False):
    cmd = [sys.executable, str(TOOL), "--out", str(out)]
    if binary is not None:
        cmd += ["--binary", str(binary)]
    if allow_mismatch:
        cmd += ["--allow-digest-mismatch"]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def to_int(limbs):
    return sum(v << (64 * i) for i, v in enumerate(limbs))


def from_limbs(n):
    return tuple((n >> (64 * i)) & MASK for i in range(4))


def parse_limbs(text):
    return tuple(int(x) for x in text.split(","))


class TestPacket(unittest.TestCase):
    def test_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "regen"
            r = run_tool(out)
            self.assertEqual(r.returncode, 0, r.stderr)
            for name in GENERATED:
                self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "a", Path(tmp) / "b"
            import os
            env_a = dict(os.environ, PYTHONHASHSEED="1", TZ="UTC")
            env_b = dict(os.environ, PYTHONHASHSEED="42", TZ="Asia/Seoul")
            for out, env in ((a, env_a), (b, env_b)):
                r = subprocess.run([sys.executable, str(TOOL), "--out", str(out)],
                                   cwd=ROOT, capture_output=True, text=True, env=env)
                self.assertEqual(r.returncode, 0, r.stderr)
            for name in GENERATED:
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes(), name)

    def test_independent_bigint_model(self):
        """Reimplement caller A/B/D outcomes with plain big integers."""
        rows = (PACKET / "cases.tsv").read_text().splitlines()[1:]
        # Helper behavior rows (products, flags) from the #160 grid, as used
        # by the packet: name -> (product, h1_flag, h2_al).
        grid = {
            "single_limb": ((35, 0, 0, 0), 0, 0),
            "b_low_zero": ((0, 35, 0, 0), 1, 0),
            "b_zero": ((0, 0, 0, 0), 1, 0),
            "two_limb_fit": ((3, 10, 8, 0), 1, 0),
            "limb_max_squared": ((1, MASK - 1, 0, 0), 0, 0),
            "max_times_two": ((MASK - 1, MASK, MASK, MASK), 1, 1),
            "four_limb_overflow": ((5, 16, 34, 60), 1, 1),
            "top_limb_product": ((0, 0, 0, 0), 1, 1),
        }
        for line in rows:
            f = line.split("\t")
            caller, case = f[0], f[1]
            if caller == "caller-A":
                p1, flag1, _ = grid[f[2]]
                p2, flag2, _ = grid[f[3]]
                stored = parse_limbs(f[4])
                s = (MOD - 1 if flag1 else to_int(p1)) + (MOD - 1 if flag2 else to_int(p2))
                if s >= MOD:
                    s = MOD - 1
                d = 0 if to_int(stored) < s else to_int(stored) - s
                self.assertEqual(f[6], ",".join(str(x) for x in from_limbs(d)), case)
            elif caller == "caller-B":
                p, flag, _ = grid[f[2]]
                stored = parse_limbs(f[4])
                pp = MOD - 1 if flag else to_int(p)
                d = 0 if to_int(stored) < pp else to_int(stored) - pp
                self.assertEqual(f[6], ",".join(str(x) for x in from_limbs(d)), case)
            elif caller == "caller-D":
                if f[2] in grid:
                    p, _flag, al = grid[f[2]]
                else:
                    p, al = parse_limbs(f[4]), 0
                if al:
                    want = "return-0"
                else:
                    want = "return-0" if to_int(p) + 10 >= MOD else "continue"
                self.assertEqual(f[6], want, case)
            elif caller == "caller-C":
                self.assertEqual(f[6], "al-not-consumed", case)
            else:
                self.fail(f"unknown caller {caller}")
        self.assertEqual(len(rows), 18)

    def test_anchor_tamper_controls(self):
        # Anchor file offsets via the shared parser's section map.
        sys.path.insert(0, str(ROOT / "tools"))
        import elf_index
        data = BINARY.read_bytes()
        sections, _entries = elf_index.unwind_index(data)
        sys.path.insert(0, str(ROOT / "tools"))
        import importlib.util
        spec = importlib.util.spec_from_file_location("gen", TOOL)
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        with tempfile.TemporaryDirectory() as tmp:
            for va, hex_bytes in gen.ANCHORS:
                bad = Path(tmp) / "bad.bin"
                blob = bytearray(data)
                off = gen.va_to_offset(sections, va)
                blob[off] ^= 0xFF
                bad.write_bytes(blob)
                r = run_tool(Path(tmp) / "o", binary=bad, allow_mismatch=True)
                self.assertNotEqual(r.returncode, 0, f"anchor {va:#x} tamper survived")

    def test_digest_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.bin"
            blob = bytearray(BINARY.read_bytes())
            blob[100] ^= 0xFF
            bad.write_bytes(blob)
            r = run_tool(Path(tmp) / "o", binary=bad)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("digest mismatch", r.stderr)

    def test_non_anchor_control_still_generates(self):
        # Flip a byte inside caller-A's window but outside every anchor.
        sys.path.insert(0, str(ROOT / "tools"))
        import elf_index
        import importlib.util
        data = BINARY.read_bytes()
        sections, _entries = elf_index.unwind_index(data)
        spec = importlib.util.spec_from_file_location("gen", TOOL)
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.bin"
            blob = bytearray(data)
            off = gen.va_to_offset(sections, 0x279D0C0 + 10)
            blob[off] ^= 0xFF
            bad.write_bytes(blob)
            r = run_tool(Path(tmp) / "o", binary=bad, allow_mismatch=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_manifest(self):
        r = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                           cwd=PACKET, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_packet_shape(self):
        sites = (PACKET / "sites.tsv").read_text().splitlines()
        self.assertEqual(len(sites), 6)  # header + 5 non-scaling sites
        import json
        ev = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(ev["sites"], 5)
        self.assertEqual(ev["census_total"], 14)
        self.assertEqual(ev["anchors"], 20)
        self.assertEqual(ev["cases"], 18)


if __name__ == "__main__":
    unittest.main()
