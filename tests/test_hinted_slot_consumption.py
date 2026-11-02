#!/usr/bin/env python3
"""Unit tests for RE-004-hinted-slot-consumption-94.

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
PACKET = ROOT / "research" / "work-items" / "RE-004-hinted-slot-consumption-94"
GEN = ROOT / "tools" / "hinted_slot_consumption.py"
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"


def run_gen(out, seed, tz):
    env = dict(os.environ, PYTHONHASHSEED=seed, TZ=tz)
    return subprocess.run(
        [sys.executable, str(GEN), "--out", str(out)],
        capture_output=True, text=True, env=env, check=False)


def read_tsv(path):
    lines = path.read_text().splitlines()
    return lines[0], lines[1:]


class TestHintedSlotConsumption(unittest.TestCase):
    def test_generator_runs(self):
        with tempfile.TemporaryDirectory() as d:
            r = run_gen(d, "1", "UTC")
            self.assertEqual(r.returncode, 0, r.stderr)
            for f in ("evidence.json", "subdtor-walk.tsv",
                      "helper-consumption.tsv", "route-census.tsv",
                      "segments.txt"):
                self.assertTrue((Path(d) / f).exists(), f)

    def test_regeneration_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a", Path(d) / "b"
            self.assertEqual(run_gen(a, "1", "UTC").returncode, 0)
            self.assertEqual(run_gen(b, "99", "Asia/Seoul").returncode, 0)
            for f in ("evidence.json", "subdtor-walk.tsv",
                      "helper-consumption.tsv", "route-census.tsv",
                      "segments.txt"):
                self.assertEqual((a / f).read_bytes(),
                                 (b / f).read_bytes(), f)

    def test_packet_matches_regeneration(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "regen"
            self.assertEqual(run_gen(out, "7", "UTC").returncode, 0)
            for f in ("evidence.json", "subdtor-walk.tsv",
                      "helper-consumption.tsv", "route-census.tsv",
                      "segments.txt"):
                self.assertEqual((out / f).read_bytes(),
                                 (PACKET / f).read_bytes(), f)

    def test_segments_match_binary(self):
        data = NODE.read_bytes()
        _, rows = read_tsv(PACKET / "segments.txt")
        self.assertEqual(len(rows), 16)
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
        self.assertEqual(claim, 175)
        self.assertEqual(anchor, 59)

    def test_counts_cross_check(self):
        ev = json.loads((PACKET / "evidence.json").read_text())
        _, walk = read_tsv(PACKET / "subdtor-walk.tsv")
        _, helper = read_tsv(PACKET / "helper-consumption.tsv")
        _, census = read_tsv(PACKET / "route-census.tsv")
        self.assertEqual(len(walk), 3)
        self.assertEqual(len(helper), 8)
        self.assertEqual(len(census), 10)
        self.assertEqual(ev["counts"]["walk_rows"], 3)
        self.assertEqual(ev["counts"]["helper_rows"], 8)
        self.assertEqual(ev["counts"]["census_rows"], 10)
        self.assertEqual(ev["counts"]["got_slots"], 10)
        self.assertEqual(len(ev["got"]["slots"]), 10)
        self.assertEqual(ev["counts"]["segments"], 16)
        self.assertEqual(ev["counts"]["claim_bytes"], 175)
        self.assertEqual(ev["counts"]["anchor_bytes"], 59)
        # The hinted slot is the helper's +8 only on the 0x37f5c80 route.
        yes = [r for r in walk if r.endswith("YES-conditional")]
        self.assertEqual(len(yes), 1)
        self.assertTrue(yes[0].startswith("0x37f5c80"))

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
