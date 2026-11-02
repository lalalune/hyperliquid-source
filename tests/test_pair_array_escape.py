#!/usr/bin/env python3
"""Unit tests for the RE-004 pair-array escape packet (node #94)."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-004-pair-array-escape-94")
GEN = os.path.join(ROOT, "tools", "pair_array_escape.py")
NODE = os.path.join(ROOT, "artifacts", "node", "94", "hl-node")
NODE_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


def run_gen(out, node=None, env_extra=None):
    cmd = [sys.executable, GEN, "--out", out]
    if node:
        cmd += ["--node", node]
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(cmd, capture_output=True, text=True, env=env,
                          cwd=ROOT)


def read_tsv(path):
    with open(path) as fh:
        lines = [ln.rstrip("\n") for ln in fh if ln.strip()]
    return lines[0].split("\t"), lines[1:]


class TestPairArrayEscape(unittest.TestCase):
    def test_node_identity(self):
        self.assertEqual(os.path.getsize(NODE), 91774280)
        h = hashlib.sha256()
        with open(NODE, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        self.assertEqual(h.hexdigest(), NODE_SHA)

    def test_regeneration_identical_and_matches_packet(self):
        with tempfile.TemporaryDirectory() as td:
            a = os.path.join(td, "a")
            b = os.path.join(td, "b")
            ra = run_gen(a, env_extra={"PYTHONHASHSEED": "1", "TZ": "UTC"})
            rb = run_gen(b, env_extra={"PYTHONHASHSEED": "99",
                                       "TZ": "Asia/Seoul"})
            self.assertEqual(ra.returncode, 0, ra.stderr)
            self.assertEqual(rb.returncode, 0, rb.stderr)
            diff = subprocess.run(["diff", "-r", a, b], capture_output=True,
                                  text=True)
            self.assertEqual(diff.returncode, 0, diff.stdout)
            for fn in ("evidence.json", "escape.tsv", "callers.tsv",
                       "forward.tsv", "dtor.tsv", "segments.txt"):
                with open(os.path.join(a, fn), "rb") as fh:
                    gen_bytes = fh.read()
                with open(os.path.join(PACKET, fn), "rb") as fh:
                    pkt_bytes = fh.read()
                self.assertEqual(gen_bytes, pkt_bytes, fn)

    def test_segment_digests(self):
        with open(NODE, "rb") as fh:
            data = fh.read()
        with open(os.path.join(PACKET, "segments.txt")) as fh:
            lines = [ln.split() for ln in fh if ln.strip()]
        self.assertEqual(lines[0][0], "seg_id")
        rows = lines[1:]
        self.assertEqual(len(rows), 28)
        claims = [r for r in rows if r[6] == "claim"]
        anchors = [r for r in rows if r[6] == "anchor"]
        self.assertEqual(len(claims), 26)
        self.assertEqual(len(anchors), 2)
        self.assertEqual(sum(int(r[3]) for r in claims), 377)
        self.assertEqual(sum(int(r[3]) for r in anchors), 44)
        for r in rows:
            sva, eva, ln, off, sha = (int(r[1], 16), int(r[2], 16),
                                      int(r[3]), int(r[4], 16), r[5])
            self.assertEqual(eva - sva, ln)
            self.assertEqual(off, sva - 0x1000)
            self.assertEqual(hashlib.sha256(data[off:off + ln]).hexdigest(),
                             sha, r[0])
        # Anchors must match #172's published digests.
        by_id = {r[0]: r[5] for r in rows}
        self.assertEqual(
            by_id["anchor-memcpy-site"],
            "3250385ac1a0ffe297516359f5b7f8f426df05b637e116243832c85fdfcffc9d")
        self.assertEqual(
            by_id["anchor-oc-pair"],
            "b459ea8d4e752a9761709bede8c1b850f0bc5e1589d02ac3588fa9a4ddcdd535")

    def test_counts(self):
        with open(os.path.join(PACKET, "evidence.json")) as fh:
            ev = json.load(fh)
        counts = ev["counts"]
        self.assertEqual(counts["segments_total"], 28)
        self.assertEqual(counts["segments_claim"], 26)
        self.assertEqual(counts["segments_anchor"], 2)
        self.assertEqual(counts["claim_bytes"], 377)
        self.assertEqual(counts["anchor_bytes"], 44)
        self.assertEqual(counts["indirect_callers"], 5)
        self.assertEqual(counts["spans_verified"], 56)
        self.assertEqual(len(ev["reachability"]["got_call_sites"]), 5)
        self.assertEqual(ev["reachability"]["relocation_hits"][0]["index"],
                         75886)
        _, callers = read_tsv(os.path.join(PACKET, "callers.tsv"))
        self.assertEqual(len(callers), 5)
        verdicts = [row.split("\t")[12] for row in callers]
        self.assertEqual(verdicts.count("NO-READ"), 4)
        self.assertEqual(verdicts.count("FORWARDED"), 1)
        _, escape = read_tsv(os.path.join(PACKET, "escape.tsv"))
        self.assertEqual(len(escape), 7)
        _, forward = read_tsv(os.path.join(PACKET, "forward.tsv"))
        self.assertEqual(len(forward), 8)
        _, dtor = read_tsv(os.path.join(PACKET, "dtor.tsv"))
        self.assertEqual(len(dtor), 10)

    def test_escape_arithmetic(self):
        self.assertEqual(0x108 + (0x388 - 0x2A0), 0x1F0)
        self.assertEqual(0x1F0 + 0x20, 0x210)
        self.assertEqual(0x1F0 + 0x28, 0x218)
        self.assertEqual(0x2A0 + 0x1198, 0x1438)
        self.assertTrue(0x2A0 <= 0x388 and 0x438 <= 0x1438)
        # Destructor loop coverage of the pair array.
        covered = set()
        r12 = 0x1B0
        while r12 < 0x11B0:
            covered.add(r12 - 0x18)
            covered.add(r12 - 0x10)
            r12 += 0x10
        for slot in range(0x1F0, 0x2A0, 8):
            self.assertIn(slot, covered)
        self.assertEqual(0x228 - 0x18, 0x210)
        self.assertEqual(0x228 - 0x10, 0x218)

    def test_tamper_control_corrupt_node(self):
        scratch = os.path.expanduser("~/workspace/scratch-hl173")
        os.makedirs(scratch, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as td:
            bad = os.path.join(td, "hl-node-bad")
            shutil.copyfile(NODE, bad)
            with open(bad, "r+b") as fh:
                # Flip a byte inside the rbx=rdi span (0x4e7d38a -> off -0x1000).
                fh.seek(0x4E7D38A - 0x1000)
                b = fh.read(1)
                fh.seek(0x4E7D38A - 0x1000)
                fh.write(bytes([b[0] ^ 0xFF]))
            r = run_gen(os.path.join(td, "out"), node=bad)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("FAIL", r.stderr + r.stdout)

    def test_tamper_control_wrong_digest(self):
        # A node file of the right size prefix but wrong content must fail.
        with tempfile.TemporaryDirectory() as td:
            bad = os.path.join(td, "hl-node-bad")
            with open(NODE, "rb") as fh:
                head = fh.read(4096)
            with open(bad, "wb") as fh:
                fh.write(head)
                fh.truncate(91774280)
            r = run_gen(os.path.join(td, "out"), node=bad)
            self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
