#!/usr/bin/env python3
"""Tests for the RE-004 destructor-guard-zero packet."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-004-destructor-guard-zero-94"
GEN = ROOT / "tools" / "destructor_guard_zero.py"
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"


def run_gen(out, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    r = subprocess.run([sys.executable, str(GEN), "--out", str(out)],
                       capture_output=True, text=True, env=env)
    return r


class TestDestructorGuardZero(unittest.TestCase):
    def test_regeneration_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            a, b = Path(td) / "a", Path(td) / "b"
            ra = run_gen(a, {"PYTHONHASHSEED": "1", "TZ": "UTC"})
            rb = run_gen(b, {"PYTHONHASHSEED": "99", "TZ": "Asia/Seoul"})
            self.assertEqual(ra.returncode, 0, ra.stderr)
            self.assertEqual(rb.returncode, 0, rb.stderr)
            for f in ("evidence.json", "guard-chain.tsv",
                      "coord-map.tsv", "segments.txt"):
                self.assertEqual((a / f).read_bytes(), (b / f).read_bytes(),
                                 f)

    def test_packet_matches_regeneration(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "regen"
            r = run_gen(out)
            self.assertEqual(r.returncode, 0, r.stderr)
            for f in ("evidence.json", "guard-chain.tsv",
                      "coord-map.tsv", "segments.txt"):
                self.assertEqual((out / f).read_bytes(),
                                 (PACKET / f).read_bytes(), f)

    def test_counts(self):
        ev = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(ev["counts"]["chain_rows"], 19)
        self.assertEqual(ev["counts"]["coord_rows"], 7)
        self.assertEqual(ev["counts"]["segments"], 18)
        self.assertEqual(ev["counts"]["claim_bytes"], 97)
        self.assertEqual(ev["counts"]["anchor_bytes"], 75)
        self.assertFalse(ev["guard"]["loop_runs"])
        self.assertEqual(ev["guard"]["value"], 0)
        chain = (PACKET / "guard-chain.tsv").read_text().splitlines()
        self.assertEqual(len(chain), 20)  # header + 19 rows
        coord = (PACKET / "coord-map.tsv").read_text().splitlines()
        self.assertEqual(len(coord), 8)  # header + 7 rows
        segs = (PACKET / "segments.txt").read_text().splitlines()
        self.assertEqual(len(segs), 19)  # header + 18 rows
        for line in segs[1:]:
            parts = line.split()
            s, e, ln = int(parts[1], 16), int(parts[2], 16), int(parts[3])
            self.assertEqual(e - s, ln)
            self.assertEqual(int(parts[4], 16), s - 0x1000)

    def test_segment_bytes_match_binary(self):
        data = NODE.read_bytes()
        self.assertEqual(len(data), 91774280)
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")
        for line in (PACKET / "segments.txt").read_text().splitlines()[1:]:
            parts = line.split()
            fo, ln, sha = int(parts[4], 16), int(parts[3]), parts[5]
            self.assertEqual(hashlib.sha256(data[fo:fo + ln]).hexdigest(),
                             sha)

    def test_tamper_control_generator_fails(self):
        # Corrupt one recorded segment digest in a copy of the
        # generator: it must fail against the real node.
        with tempfile.TemporaryDirectory() as td:
            gen = Path(td) / "gen.py"
            src = GEN.read_text()
            old = "70ea794ed55d40c5ba40188f2e1a0451d8db3b77044fef56539caa7b9d32d053"
            self.assertIn(old, src)
            gen.write_text(src.replace(old, "00" + old[2:], 1))
            out = Path(td) / "out"
            r = subprocess.run([sys.executable, str(gen), "--out", str(out),
                                "--node", str(NODE)],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("digest mismatch", r.stderr)

    def test_tamper_control_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "pkt"
            shutil.copytree(PACKET, d)
            (d / "segments.txt").write_text(
                (d / "segments.txt").read_text().replace(
                    "guard-cmp-je", "guard-cmp-jx", 1))
            r = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                               cwd=d, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
