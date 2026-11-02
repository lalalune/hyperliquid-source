#!/usr/bin/env python3
"""Unit tests for RE-004-downstream-stale-readers-94.

Regeneration + tamper controls. Run from the repository root:
  python3 -m unittest tests.test_downstream_stale_readers
"""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-004-downstream-stale-readers-94"
GEN = ROOT / "tools/downstream_stale_readers.py"
NODE = ROOT / "artifacts/node/94/hl-node"


def run_gen(out, env_extra=None):
    env = {"PYTHONHASHSEED": "1", "TZ": "UTC", "PATH": "/usr/bin:/bin"}
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(GEN), "--out", str(out)],
        capture_output=True, text=True, env=env, cwd=str(ROOT))


def load_segments(path):
    rows = []
    for line in open(path).read().splitlines()[1:]:
        parts = line.split("\t")
        rows.append(parts)
    return rows


class TestDownstreamStaleReaders(unittest.TestCase):
    def test_generator_exits_zero(self):
        with tempfile.TemporaryDirectory() as td:
            r = run_gen(td)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_deterministic_regeneration(self):
        with tempfile.TemporaryDirectory() as td:
            a, b = Path(td) / "a", Path(td) / "b"
            self.assertEqual(run_gen(a).returncode, 0)
            r = run_gen(b, {"PYTHONHASHSEED": "99", "TZ": "Asia/Seoul"})
            self.assertEqual(r.returncode, 0)
            d = subprocess.run(["diff", "-r", str(a), str(b)],
                               capture_output=True, text=True)
            self.assertEqual(d.returncode, 0, d.stdout)

    def test_packet_matches_regeneration(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "regen"
            self.assertEqual(run_gen(out).returncode, 0)
            for fn in ["evidence.json", "reader-sites.tsv",
                       "propagation.tsv", "segments.txt"]:
                self.assertEqual(
                    (out / fn).read_bytes(), (PACKET / fn).read_bytes(), fn)
            d = subprocess.run(
                ["diff", "-r", str(out), str(PACKET),
                 "--exclude=README.md", "--exclude=MANIFEST.sha256"],
                capture_output=True, text=True)
            self.assertEqual(d.returncode, 0, d.stdout)

    def test_segment_bytes_match_binary(self):
        blob = NODE.read_bytes()
        for parts in load_segments(PACKET / "segments.txt"):
            name, kind, start, end, ln, sha, hexs = parts
            s, e = int(start, 16), int(end, 16)
            self.assertEqual(e - s, int(ln), name)
            raw = blob[s - 0x1000:e - 0x1000]
            self.assertEqual(raw.hex(), hexs, name)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), sha, name)

    def test_tallies(self):
        sites = (PACKET / "reader-sites.tsv").read_text().splitlines()
        self.assertEqual(len(sites) - 1, 11)
        verdicts = [r.split("\t")[8] for r in sites[1:]]
        self.assertEqual(verdicts.count("READ"), 3)
        self.assertEqual(verdicts.count("NO-READ"), 8)
        prop = (PACKET / "propagation.tsv").read_text().splitlines()
        self.assertEqual(len(prop) - 1, 6)
        per_site = {}
        for r in prop[1:]:
            p = r.split("\t")
            per_site[p[0]] = per_site.get(p[0], 0) + int(p[3])
        self.assertEqual(per_site, {k: 22 for k in per_site})
        segs = load_segments(PACKET / "segments.txt")
        self.assertEqual(len(segs), 46)
        kinds = [s[1] for s in segs]
        self.assertEqual(kinds.count("call"), 11)
        self.assertEqual(kinds.count("read"), 14)
        self.assertEqual(kinds.count("store"), 14)
        self.assertEqual(kinds.count("anchor"), 7)
        claim = sum(int(s[4]) for s in segs if s[1] != "anchor")
        anchor = sum(int(s[4]) for s in segs if s[1] == "anchor")
        self.assertEqual(claim, 211)
        self.assertEqual(anchor, 23)

    def test_call_sites_inside_caller_fdes(self):
        for r in (PACKET / "reader-sites.tsv").read_text().splitlines()[1:]:
            p = r.split("\t")
            start, end, call = int(p[1], 16), int(p[2], 16), int(p[4], 16)
            self.assertTrue(start <= call < end, p[0])

    def test_tamper_generator_expected_hex_fails(self):
        spec = importlib.util.spec_from_file_location("ds_gen", str(GEN))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.SEGMENTS = [("x", "call", 0x4E6FF83, "e8c8fdfffe")] + list(mod.SEGMENTS[1:])
        with tempfile.TemporaryDirectory() as td:
            sys.argv = ["gen", "--out", td]
            self.assertNotEqual(mod.main(), 0)

    def test_tamper_segment_digest_fails(self):
        blob = NODE.read_bytes()
        rows = load_segments(PACKET / "segments.txt")
        name, kind, start, end, ln, sha, hexs = rows[0]
        bad_hex = ("0" if hexs[0] != "0" else "1") + hexs[1:]
        raw = bytes.fromhex(bad_hex)
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), sha)

    def test_evidence_json_consistent(self):
        ev = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(ev["call_sites"], 11)
        self.assertEqual(ev["caller_fdes"], 9)
        self.assertEqual(ev["read_sites"], 3)
        self.assertEqual(ev["no_read_sites"], 8)
        self.assertEqual(ev["segments"]["total"], 46)
        self.assertEqual(len(ev["segments_detail"]), 46)


if __name__ == "__main__":
    unittest.main()
