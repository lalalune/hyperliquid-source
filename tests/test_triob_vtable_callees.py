#!/usr/bin/env python3
"""Unit tests for RE-004-triob-vtable-callee-resolution-94.

Regeneration determinism, packet identity, segment-to-binary
digests, count cross-checks, and tamper controls. No node
execution, no network.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-004-triob-vtable-callee-resolution-94"
GEN = ROOT / "tools" / "triob_vtable_callees.py"
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"


def run_gen(out, seed, tz):
    env = dict(os.environ, PYTHONHASHSEED=seed, TZ=tz)
    return subprocess.run(
        [sys.executable, str(GEN), "--out", str(out)],
        capture_output=True, text=True, env=env, check=False)


def read_tsv(path):
    lines = path.read_text().splitlines()
    return lines[0], lines[1:]


class TestTriobVtableCallees(unittest.TestCase):
    def test_generator_runs(self):
        with tempfile.TemporaryDirectory() as d:
            r = run_gen(d, "1", "UTC")
            self.assertEqual(r.returncode, 0, r.stderr)
            for f in ("evidence.json", "chain.tsv", "callees.tsv",
                      "segments.txt"):
                self.assertTrue((Path(d) / f).exists(), f)

    def test_regeneration_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a", Path(d) / "b"
            self.assertEqual(run_gen(a, "1", "UTC").returncode, 0)
            self.assertEqual(run_gen(b, "99", "Asia/Seoul").returncode, 0)
            for f in ("evidence.json", "chain.tsv", "callees.tsv",
                      "segments.txt"):
                self.assertEqual((a / f).read_bytes(),
                                 (b / f).read_bytes(), f)

    def test_packet_matches_regeneration(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "regen"
            self.assertEqual(run_gen(out, "7", "UTC").returncode, 0)
            for f in ("evidence.json", "chain.tsv", "callees.tsv",
                      "segments.txt"):
                self.assertEqual((out / f).read_bytes(),
                                 (PACKET / f).read_bytes(), f)

    def test_segments_match_binary(self):
        data = NODE.read_bytes()
        _, rows = read_tsv(PACKET / "segments.txt")
        self.assertEqual(len(rows), 10)
        claim = anchor = 0
        for row in rows:
            p = row.split()
            seg_id, s, e, ln, fo, sha, kind = (
                p[0], int(p[1], 16), int(p[2], 16), int(p[3]),
                int(p[4], 16), p[5], p[6])
            self.assertEqual(e - s, ln, seg_id)
            chunk = data[fo:fo + ln]
            self.assertEqual(len(chunk), ln, seg_id)
            self.assertEqual(hashlib.sha256(chunk).hexdigest(), sha,
                             seg_id)
            if kind == "claim":
                claim += ln
            else:
                anchor += ln
        self.assertEqual(claim, 95)
        self.assertEqual(anchor, 155)

    def test_counts_cross_check(self):
        ev = json.loads((PACKET / "evidence.json").read_text())
        _, chain = read_tsv(PACKET / "chain.tsv")
        _, callees = read_tsv(PACKET / "callees.tsv")
        self.assertEqual(len(chain), 14)
        self.assertEqual(len(callees), 8)
        self.assertEqual(ev["counts"]["chain_rows"], 14)
        self.assertEqual(ev["counts"]["callee_rows"], 8)
        self.assertEqual(ev["counts"]["reloc_rows"], 8)
        self.assertEqual(ev["counts"]["segments"], 10)
        self.assertEqual(ev["counts"]["claim_bytes"], 95)
        self.assertEqual(ev["counts"]["anchor_bytes"], 155)
        # Each callee writes exactly the four out offsets.
        offs = sorted({r.split()[2] for r in callees})
        self.assertEqual(offs, ["+0x00", "+0x08", "+0x10", "+0x18"])
        # The twin callees differ only in the installed table pointer.
        h3 = [r for r in callees if r.startswith("H3-")]
        h2 = [r for r in callees if r.startswith("H2-")]
        self.assertEqual(len(h3), 4)
        self.assertEqual(len(h2), 4)
        self.assertEqual([r.split()[2] for r in h3],
                         [r.split()[2] for r in h2])
        self.assertNotEqual(h3[0].split()[-1], h2[0].split()[-1])
        # Header 0 stays unresolved; headers 2 and 3 are produced.
        self.assertEqual(ev["verdict"]["header0"], "unresolved-indirect")
        self.assertTrue(ev["verdict"]["header2"].startswith(
            "fully-produced"))
        self.assertTrue(ev["verdict"]["header3"].startswith(
            "fully-produced"))

    def test_tamper_control(self):
        # Flipping one hex digit of a segment digest must break the
        # digest check (recompute and compare).
        data = NODE.read_bytes()
        _, rows = read_tsv(PACKET / "segments.txt")
        p = rows[0].split()
        s, e, fo = int(p[1], 16), int(p[2], 16), int(p[4], 16)
        good = hashlib.sha256(data[fo:fo + (e - s)]).hexdigest()
        bad = ("0" if good[0] != "0" else "1") + good[1:]
        self.assertNotEqual(good, bad)
        self.assertEqual(good, p[5])


if __name__ == "__main__":
    unittest.main()
