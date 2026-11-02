"""Unit tests for the RE-004 tag-5 resolver twins packet."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from tag5_resolver_twins94 import (  # noqa: E402
    BIG_SITES,
    CONST_HI,
    CONST_LO,
    TWINS,
    build_cases,
)

ROOT = Path(__file__).resolve().parent.parent
PACKET = ROOT / "research/work-items/RE-004-tag5-resolver-twins-94"
TOOL = ROOT / "tools/tag5_resolver_twins94.py"
BINARY = ROOT / "artifacts/node/94/hl-node"

FILES = ["evidence.json", "sites.tsv", "cases.tsv", "windows.txt"]


def run_tool(out, extra=None, env=None):
    cmd = [sys.executable, str(TOOL), "--out", str(out)] + (extra or [])
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def resolver_outcome(twin, tag, header4, vectors_match, transform_tag):
    """Independent re-implementation of the twin routing model.

    Returns (output_object, obj_writes). Transform results are opaque
    values; only routing and overwrite extents are modeled.
    """
    if tag != 5:
        return ("copied-fields", "none")
    if not header4:
        return ("tag-5-as-is", "none")
    if vectors_match:
        return ("tag-5-resolved", "[obj]=1;[obj+0x8..0x38]=decoded")
    if twin == "twin-A":
        return ("tag-5-resolved", "[obj+0x0..0x40]=transform_A(vectors)")
    if transform_tag == "4":
        return ("tag-5-resolved",
                "[obj+0x0]=1;[obj+0x8..0x40]=second_transform")
    return ("tag-5-resolved", "[obj+0x0..0x40]=transform_B(vectors)")


class TestPacket(unittest.TestCase):
    def test_regeneration_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = run_tool(tmp)
            self.assertEqual(r.returncode, 0, r.stderr)
            for name in FILES:
                self.assertEqual(digest(Path(tmp) / name), digest(PACKET / name), name)

    def test_cross_env_determinism(self):
        import os
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            env_a = dict(os.environ, PYTHONHASHSEED="1", TZ="UTC")
            env_b = dict(os.environ, PYTHONHASHSEED="42", TZ="Asia/Seoul")
            self.assertEqual(run_tool(a, env=env_a).returncode, 0)
            self.assertEqual(run_tool(b, env=env_b).returncode, 0)
            for name in FILES:
                self.assertEqual(digest(Path(a) / name), digest(Path(b) / name), name)

    def test_manifest(self):
        lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        self.assertEqual(len(lines), 5)
        for line in lines:
            want, name = line.split("  ")
            self.assertEqual(digest(PACKET / name), want, name)

    def test_packet_shape(self):
        evidence = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(evidence["decoder_census"],
                         {"total": 30, "dec-A": 15, "dec-B": 15,
                          "wrappers": 12, "twins": 2, "big_function_sites": 16})
        self.assertEqual(evidence["e9_tail_jump_callers"], 0)
        self.assertEqual(len(evidence["windows"]), 2)
        self.assertEqual(evidence["vector_constants"]["0x204be0"],
                         "e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(evidence["vector_constants"]["0x206160"],
                         "c5d2460186f7233c927e7db2dcc703c0")
        sites = (PACKET / "sites.tsv").read_text().splitlines()
        self.assertEqual(len(sites), 3)  # header + 2
        cases = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(len(cases), 10)  # header + 9
        windows = (PACKET / "windows.txt").read_text().splitlines()
        self.assertEqual(len(windows), 2)
        self.assertIn("length=421", windows[0])
        self.assertIn("length=527", windows[1])
        # Every case row lists the untouched ranges.
        for row in cases[1:]:
            self.assertTrue(row.endswith("difference/counter/flag"), row)

    def test_case_table_matches_model(self):
        rows = build_cases()
        self.assertEqual(len(rows), 9)
        tsv = (PACKET / "cases.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(tsv), 9)
        for spec, line in zip(rows, tsv):
            twin, case, tag, header4, match, ttag, out, writes, untouched = spec
            fields = line.split("\t")
            self.assertEqual(fields[0], twin)
            self.assertEqual(fields[1], case)
            self.assertEqual(fields[2], str(tag))
            model_out, model_writes = resolver_outcome(
                twin, tag, header4 == "1", match == "1", ttag)
            self.assertEqual(fields[6], model_out, case)
            self.assertEqual(fields[7], model_writes, case)
            self.assertEqual(fields[8], untouched, case)

    def test_twin_identity_from_binary(self):
        import elf_index
        data = BINARY.read_bytes()
        sections, _entries = elf_index.unwind_index(data)

        def rd(va, n):
            for s in sections:
                if s["type"] == 8:
                    continue
                if s["address"] <= va < s["address"] + s["size"]:
                    off = s["offset"] + (va - s["address"])
                    return data[off:off + n]
            raise ValueError(hex(va))
        # Tag != 5 copy blocks byte-identical.
        self.assertEqual(rd(0x2788415, 51), rd(0x27885CB, 51))
        # Match-path copy blocks byte-identical.
        self.assertEqual(rd(0x2788467, 29), rd(0x2788620, 29))
        # Vector-compare blocks identical modulo rip displacement bytes.
        a = bytearray(rd(0x278838B, 47))
        b = bytearray(rd(0x278853B, 47))
        for i in range(47):
            if i in (16, 17, 18, 19, 24, 25, 26, 27, 42, 43, 44, 45):
                continue  # rip-relative / branch displacements (position-dependent)
            self.assertEqual(a[i], b[i], f"vec-cmp byte {i}")
        # Constants at the recorded addresses.
        self.assertEqual(rd(CONST_HI, 16).hex(), "e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(rd(CONST_LO, 16).hex(), "c5d2460186f7233c927e7db2dcc703c0")
        # Window digests match the packet.
        self.assertEqual(hashlib.sha256(rd(0x2788350, 421)).hexdigest(),
                         "95e6e17834b24e0394a2f1395986d2660ed44c97a25c8233358527f362e124f4")
        self.assertEqual(hashlib.sha256(rd(0x2788500, 527)).hexdigest(),
                         "adfa83aad4c417e53d2573ec2a034c3aac90b5c1f256b319e8503c9e88d7c519")

    def test_anchor_tamper_controls(self):
        # Anchor control: flip twin-A's tag-compare byte (cmp al,5 -> cmp al,6).
        # The digest gate must be bypassed for the anchor check to be reached.
        import elf_index
        data = BINARY.read_bytes()
        sections, _entries = elf_index.unwind_index(data)
        off = None
        for s in sections:
            if s["type"] == 8:
                continue
            if s["address"] <= 0x278836F < s["address"] + s["size"]:
                off = s["offset"] + (0x278836F - s["address"])
        self.assertIsNotNone(off)
        self.assertEqual(data[off:off + 2], bytes.fromhex("3c05"))
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad-node"
            bad.write_bytes(data[:off] + b"\x06" + data[off + 1:])
            r = subprocess.run(
                [sys.executable, str(TOOL), "--out", str(Path(tmp) / "o"),
                 "--binary", str(bad), "--allow-digest-mismatch"],
                cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("anchor mismatch", r.stderr + r.stdout)
        # Non-anchor control: flip a byte in twin-A's unwind landing pad
        # (after the main ret, not anchor-checked). Generation must succeed.
        pad_va = 0x27884A1
        off2 = None
        for s in sections:
            if s["type"] == 8:
                continue
            if s["address"] <= pad_va < s["address"] + s["size"]:
                off2 = s["offset"] + (pad_va - s["address"])
        with tempfile.TemporaryDirectory() as tmp:
            ok = Path(tmp) / "ok-node"
            ok.write_bytes(data[:off2] + bytes([data[off2] ^ 0x01]) + data[off2 + 1:])
            r = subprocess.run(
                [sys.executable, str(TOOL), "--out", str(Path(tmp) / "o"),
                 "--binary", str(ok), "--allow-digest-mismatch"],
                cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_census_counts(self):
        self.assertEqual(len(BIG_SITES), 16)
        self.assertEqual(len(TWINS), 2)
        big_a = sum(1 for _s, d, _fs, _fe in BIG_SITES if d == 0x2787460)
        big_b = sum(1 for _s, d, _fs, _fe in BIG_SITES if d == 0x2786DD0)
        self.assertEqual((big_a, big_b), (8, 8))
        # 12 wrappers (6/6) + 2 twins (1/1) + 16 big (8/8) = 30 (15/15).
        self.assertEqual(12 + 2 + 16, 30)


if __name__ == "__main__":
    unittest.main()
