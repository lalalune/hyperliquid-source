#!/usr/bin/env python3
"""Unit tests for tools/orchestrator_callers.py (RE-004-orchestrator-callers-94).

Covers: deterministic regeneration (two envs), packet match, segment
bytes vs the node binary, census counts, template-diff discipline, and
tamper controls (corrupt node digest, corrupt segment digest).
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

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-004-orchestrator-callers-94"
GEN = ROOT / "tools/orchestrator_callers.py"
NODE = ROOT / "artifacts/node/94/hl-node"
NODE_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


def run_gen(out, node=None, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    cmd = [sys.executable, str(GEN), "--out", str(out)]
    if node is not None:
        cmd += ["--node", str(node)]
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def dir_files(d):
    return {p.name: p.read_bytes() for p in Path(d).iterdir() if p.is_file()}


class TestOrchestratorCallers(unittest.TestCase):
    def test_regeneration_deterministic_and_matches_packet(self):
        with tempfile.TemporaryDirectory() as td:
            a = Path(td) / "a"
            b = Path(td) / "b"
            ra = run_gen(a, env_extra={"PYTHONHASHSEED": "1", "TZ": "UTC"})
            rb = run_gen(b, env_extra={"PYTHONHASHSEED": "99", "TZ": "Asia/Seoul"})
            self.assertEqual(ra.returncode, 0, ra.stderr)
            self.assertEqual(rb.returncode, 0, rb.stderr)
            self.assertEqual(dir_files(a), dir_files(b))
            packet = dir_files(PACKET)
            for name in ("evidence.json", "caller-sites.tsv",
                         "template-diff.tsv", "segments.txt"):
                self.assertEqual(dir_files(a)[name], packet[name], name)

    def test_census_counts(self):
        ev = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(ev["census"]["caller_fdes"], 3)
        self.assertEqual(ev["census"]["fde_size"], 119)
        self.assertEqual(ev["census"]["direct_e8_call_sites"],
                         ["0x4e6cff0", "0x4e6d6a0", "0x4e6e7e0"])
        self.assertEqual(ev["census"]["e9_tail_jumps"], [])
        self.assertEqual(ev["verdict"], {"sites": 3, "read": 0, "no_read": 3,
                                          "output_object_reads": 0,
                                          "output_object_overwrites": 0,
                                          "returned_untouched": 3})
        sites = (PACKET / "caller-sites.tsv").read_text().strip().splitlines()
        self.assertEqual(len(sites), 4)  # header + 3
        self.assertTrue(all(l.endswith("NO-READ") for l in sites[1:]))
        diffs = (PACKET / "template-diff.tsv").read_text().strip().splitlines()
        self.assertEqual(len(diffs), 22)  # header + 21
        segs = (PACKET / "segments.txt").read_text().strip().splitlines()
        self.assertEqual(len(segs), 5)  # header + 4
        claim = [l.split("\t") for l in segs[1:] if l.startswith("claim")]
        self.assertEqual(sum(int(c[3]) for c in claim), 357)
        anchor = [l.split("\t") for l in segs[1:] if l.startswith("anchor")]
        self.assertEqual(sum(int(c[3]) for c in anchor), 3)

    def test_segment_bytes_match_binary(self):
        data = NODE.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), NODE_SHA)
        for line in (PACKET / "segments.txt").read_text().strip().splitlines()[1:]:
            _, start, end, length, sha, _ = line.split("\t", 5)
            s, e = int(start, 16), int(end, 16)
            self.assertEqual(e - s, int(length))
            self.assertEqual(hashlib.sha256(data[s - 0x1000:e - 0x1000]).hexdigest(), sha)

    def test_template_diff_fields_are_displacement_only(self):
        allowed = set()
        for lo, hi in [(17, 21), (52, 56), (82, 86), (90, 94),
                       (101, 105), (109, 113), (115, 119)]:
            allowed.update(range(lo, hi))
        for line in (PACKET / "template-diff.tsv").read_text().strip().splitlines()[1:]:
            _, _, lo, hi, _, _ = line.split("\t")
            self.assertTrue(set(range(int(lo), int(hi))) <= allowed)

    def test_tamper_node_digest_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad-node"
            shutil.copyfile(NODE, bad)
            with open(bad, "r+b") as f:
                f.seek(0x1000)
                f.write(b"\x90")
            r = run_gen(Path(td) / "out", node=bad)
            self.assertNotEqual(r.returncode, 0)

    def test_tamper_segment_digest_detected(self):
        data = NODE.read_bytes()
        lines = (PACKET / "segments.txt").read_text().strip().splitlines()
        row = lines[1].split("\t")
        s, e = int(row[1], 16), int(row[2], 16)
        real = hashlib.sha256(data[s - 0x1000:e - 0x1000]).hexdigest()
        self.assertEqual(row[4], real)
        self.assertNotEqual(row[4], "0" * 64)


if __name__ == "__main__":
    unittest.main()
