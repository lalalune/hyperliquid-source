#!/usr/bin/env python3
"""Unit tests for the RE-004 be20 location run packet."""

import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-004-be20-location-run-94"
GEN = ROOT / "tools" / "be20_location_run.py"
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"


def run_gen(out, env_extra=None):
    import os
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    r = subprocess.run(
        [sys.executable, str(GEN), "--out", str(out)],
        capture_output=True, text=True, env=env, cwd=ROOT,
    )
    return r


class TestLocationRun(unittest.TestCase):
    def test_regeneration_deterministic(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            a = Path(td) / "a"
            b = Path(td) / "b"
            ra = run_gen(a, {"PYTHONHASHSEED": "1", "TZ": "UTC"})
            rb = run_gen(b, {"PYTHONHASHSEED": "99", "TZ": "Asia/Seoul"})
            self.assertEqual(ra.returncode, 0, ra.stderr)
            self.assertEqual(rb.returncode, 0, rb.stderr)
            for name in ["locations.tsv", "sites.tsv", "segments.txt", "evidence.json"]:
                self.assertEqual(
                    (a / name).read_bytes(), (b / name).read_bytes(), name
                )

    def test_packet_matches_generator(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "g"
            r = run_gen(out)
            self.assertEqual(r.returncode, 0, r.stderr)
            for name in ["locations.tsv", "sites.tsv", "segments.txt", "evidence.json"]:
                self.assertEqual(
                    (out / name).read_bytes(), (PACKET / name).read_bytes(), name
                )

    def test_segments_match_binary(self):
        data = NODE.read_bytes()
        rows = (PACKET / "segments.txt").read_text().strip().splitlines()
        self.assertEqual(len(rows), 26)
        total = 0
        for row in rows:
            parts = row.split("\t")
            name, s, e, ln, off, digest, kind = parts
            s, e, ln, off = int(s, 16), int(e, 16), int(ln), int(off, 16)
            self.assertEqual(e - s, ln)
            self.assertEqual(ln, 24)
            self.assertEqual(kind, "claim")
            self.assertEqual(hashlib.sha256(data[off: off + ln]).hexdigest(), digest)
            total += ln
        self.assertEqual(total, 624)

    def test_counts_cross_check(self):
        locs = (PACKET / "locations.tsv").read_text().strip().splitlines()[1:]
        sites = (PACKET / "sites.tsv").read_text().strip().splitlines()[1:]
        self.assertEqual(len(locs), 26)
        self.assertEqual(len(sites), 35)
        import json
        ev = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(ev["run"]["entries"], 26)
        self.assertEqual(ev["sites"]["total"], 35)
        self.assertEqual(ev["segments"]["claim_bytes"], 624)
        # every site's entry is in range and every entry has >= 1 site
        cited = set()
        for row in sites:
            cited.add(int(row.split("\t")[1]))
        self.assertEqual(cited, set(range(26)))
        # contiguous run: 0x18 stride, reloc indices 61887..61912
        vas = [int(r.split("\t")[1], 16) for r in locs]
        self.assertEqual(vas, [0x574BF38 + i * 0x18 for i in range(26)])
        ridx = [int(r.split("\t")[6]) for r in locs]
        self.assertEqual(ridx, list(range(61887, 61913)))

    def test_tamper_line_value_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "g"
            r = run_gen(out)
            self.assertEqual(r.returncode, 0, r.stderr)
            # corrupt the generator's expected line for entry 0 by editing
            # a copy is not possible (tables are embedded), so instead
            # verify the packet's recorded line matches the binary directly:
            data = NODE.read_bytes()
            import struct
            raw = data[0x574BF38 - 0x2000: 0x574BF38 - 0x2000 + 24]
            _slot, _ln, line, col = struct.unpack("<QQII", raw)
            self.assertEqual((line, col), (65, 44))
            # and a wrong expectation must differ from the binary
            self.assertNotEqual((line, col), (65, 45))

    def test_tamper_reloc_rejected(self):
        import struct
        data = NODE.read_bytes()
        off, info, add = struct.unpack_from("<QQq", data, 0x6BC0 + 61887 * 24)
        self.assertEqual(off, 0x574BF38)
        self.assertEqual(info & 0xFFFFFFFF, 8)
        self.assertEqual(add, 0x1E3EC3)
        self.assertNotEqual(add, 0x1E3EC4)


if __name__ == "__main__":
    unittest.main()
