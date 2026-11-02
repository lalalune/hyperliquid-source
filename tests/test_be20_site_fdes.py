#!/usr/bin/env python3
"""Tests for RE-004-be20-site-fdes-94 (tools/be20_site_fdes.py).

Regeneration + packet match + segment-binary match + count
cross-checks + tamper controls. The node binary is read from the
repository (artifacts/node/94/hl-node); tamper controls run the
generator against corrupted node copies in a temp dir.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-004-be20-site-fdes-94"
GEN = ROOT / "tools" / "be20_site_fdes.py"
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"


def run_gen(out, node=None):
    cmd = [sys.executable, str(GEN), "--out", str(out)]
    if node is not None:
        cmd += ["--node", str(node)]
    return subprocess.run(cmd, capture_output=True, text=True)


class TestSiteFdes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="site_fdes_"))
        r = run_gen(cls.tmp / "regen")
        assert r.returncode == 0, r.stderr
        cls.regen = cls.tmp / "regen"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_regeneration_matches_packet(self):
        for name in ("sites.tsv", "fdes.tsv", "segments.txt", "evidence.json"):
            regen = (self.regen / name).read_bytes()
            packet = (PACKET / name).read_bytes()
            self.assertEqual(regen, packet, name)

    def test_deterministic_regeneration(self):
        out2 = self.tmp / "regen2"
        r = run_gen(out2)
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in ("sites.tsv", "fdes.tsv", "segments.txt", "evidence.json"):
            self.assertEqual((out2 / name).read_bytes(),
                             (self.regen / name).read_bytes(), name)

    def test_segment_bytes_match_binary(self):
        data = NODE.read_bytes()
        for line in (PACKET / "segments.txt").read_text().splitlines():
            p = line.split("\t")
            name, st, en, ln, off, digest, kind = p[0], int(p[1], 16), \
                int(p[2], 16), int(p[3]), int(p[4], 16), p[5], p[6]
            self.assertEqual(en - st, ln)
            self.assertEqual(off, st - 0x1000)
            b = data[off:off + ln]
            self.assertEqual(len(b), ln)
            self.assertEqual(hashlib.sha256(b).hexdigest(), digest, name)
            self.assertEqual(kind, "claim")

    def test_counts_cross_check(self):
        sites = (PACKET / "sites.tsv").read_text().splitlines()[1:]
        fdes = (PACKET / "fdes.tsv").read_text().splitlines()[1:]
        segs = (PACKET / "segments.txt").read_text().splitlines()
        self.assertEqual(len(sites), 35)
        self.assertEqual(len(fdes), 11)
        self.assertEqual(len(segs), 2)
        self.assertEqual(sum(int(l.split("\t")[3]) for l in segs), 34)
        # Per-FDE site counts sum to 35 and match sites.tsv.
        from collections import Counter
        per_fde = Counter()
        for line in sites:
            p = line.split("\t")
            per_fde[(p[5], p[6])] += 1
        for line in fdes:
            p = line.split("\t")
            self.assertEqual(int(p[2]), int(p[1], 16) - int(p[0], 16))
            self.assertEqual(per_fde[(p[0], p[1])], int(p[3]))
        self.assertEqual(sum(per_fde.values()), 35)
        # Multi-FDE entries: 19/20/21 in 3 FDEs, 22 in 4.
        entry_fdes = {}
        for line in sites:
            p = line.split("\t")
            entry_fdes.setdefault(int(p[1]), set()).add((p[5], p[6]))
        self.assertEqual({len(entry_fdes[e]) for e in (19, 20, 21)}, {3})
        self.assertEqual(len(entry_fdes[22]), 4)
        # The funnel FDE holds all 13 continuation sites + entry 11.
        funnel = [l for l in sites
                  if l.split("\t")[5] == "0x4e79b00"]
        self.assertEqual(len(funnel), 14)
        follows = Counter(l.split("\t")[3] for l in sites)
        self.assertEqual(follows["indirect"], 22)
        self.assertEqual(follows["jmp-cont"], 12)
        self.assertEqual(follows["fallthrough-cont"], 1)
        ev = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(ev["sites"], 35)
        self.assertEqual(ev["fdes"], 11)
        self.assertEqual(ev["fde_total"], 121299)
        self.assertEqual(ev["claim_bytes"], 34)
        self.assertEqual(ev["anchors"], 0)

    def test_tamper_flipped_funnel_byte_fails(self):
        bad = self.tmp / "node-flipped"
        data = bytearray(NODE.read_bytes())
        data[0x4E7A4BD - 0x1000] ^= 0xFF
        bad.write_bytes(data)
        r = run_gen(self.tmp / "bad-out", node=bad)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL", r.stderr or r.stdout)

    def test_tamper_wrong_digest_fails(self):
        tiny = self.tmp / "node-tiny"
        tiny.write_bytes(b"not a node")
        r = run_gen(self.tmp / "bad-out2", node=tiny)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
