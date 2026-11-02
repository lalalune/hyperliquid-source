#!/usr/bin/env python3
"""Tests for tools/oc_table_builder.py (RE-004-oc-table-builder-94).

Regeneration determinism, segment-byte identity against the node
binary, packet counts, and tamper controls. Static checks only;
the node binary is never executed.
"""
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-004-oc-table-builder-94"
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"
GEN = ROOT / "tools" / "oc_table_builder.py"


def run_gen(out):
    env = {"PYTHONHASHSEED": "1", "TZ": "UTC", "PATH": "/usr/bin:/bin"}
    r = subprocess.run([sys.executable, str(GEN), "--out", str(out)],
                       capture_output=True, text=True, env=env, cwd=ROOT)
    assert r.returncode == 0, r.stderr
    return out


class TestOcTableBuilder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.a = run_gen(Path(cls.tmp.name) / "a")
        cls.b = run_gen(Path(cls.tmp.name) / "b")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_deterministic_regeneration(self):
        for name in ("evidence.json", "table.tsv", "pairs.tsv",
                     "builder-leas.tsv", "sites.tsv", "segments.txt"):
            self.assertEqual((self.a / name).read_bytes(),
                             (self.b / name).read_bytes(), name)

    def test_packet_matches_regeneration(self):
        for name in ("evidence.json", "table.tsv", "pairs.tsv",
                     "builder-leas.tsv", "sites.tsv", "segments.txt"):
            self.assertEqual((PACKET / name).read_bytes(),
                             (self.a / name).read_bytes(), name)

    def test_counts(self):
        table = (PACKET / "table.tsv").read_text().splitlines()
        self.assertEqual(len(table) - 1, 11)
        pairs = (PACKET / "pairs.tsv").read_text().splitlines()
        self.assertEqual(len(pairs) - 1, 11)
        leas = (PACKET / "builder-leas.tsv").read_text().splitlines()
        self.assertEqual(len(leas) - 1, 21)
        segs = (PACKET / "segments.txt").read_text().splitlines()
        self.assertEqual(len(segs) - 1, 7)
        ev = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(ev["segments"]["claim_bytes"], 641)
        self.assertEqual(ev["scans"]["rip_census_sites"], 29)
        # oc element is element 6 with the oc trio in order oc3, oc2, oc1
        row6 = table[7].split("\t")
        self.assertEqual(row6[0], "6")
        self.assertEqual(row6[1], "0x574bd30")
        self.assertEqual(row6[2:], ["0x4e6e7d0", "0x4e6d690", "0x4e6cfe0"])
        # oc pair is pair 3 at output offset 0x20
        prow = pairs[3].split("\t")
        self.assertEqual(prow[0], "3")
        self.assertEqual(prow[1], "0x20")
        self.assertEqual(prow[3], "6")

    def test_segments_match_binary(self):
        data = NODE.read_bytes()
        for line in (PACKET / "segments.txt").read_text().splitlines()[1:]:
            parts = line.split()
            _sid, sva, eva, length, off, digest, _kind = parts
            sva, eva, length, off = int(sva, 16), int(eva, 16), int(length), int(off, 16)
            self.assertEqual(eva - sva, length)
            self.assertEqual(hashlib.sha256(data[off:off + length]).hexdigest(), digest)

    def test_tamper_table_flag(self):
        # flipping the table flag qword must make the generator fail
        import importlib.util
        spec = importlib.util.spec_from_file_location("oc_gen", GEN)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        data = bytearray(NODE.read_bytes())
        off = 0x574BC10 - 0x2000 + 16
        self.assertEqual(struct.unpack("<Q", bytes(data[off:off + 8]))[0], 1)
        data[off] ^= 0x01
        tampered = Path(self.tmp.name) / "tampered-node"
        tampered.write_bytes(bytes(data))
        mod.NODE = tampered
        # re-point the digest check at the tampered bytes so the run
        # reaches the table-flag check (and must fail there)
        mod.NODE_SHA = hashlib.sha256(bytes(data)).hexdigest()
        sys_argv = sys.argv
        sys.argv = ["oc_table_builder.py", "--out",
                    str(Path(self.tmp.name) / "t")]
        try:
            with self.assertRaises(SystemExit):
                mod.main()
        finally:
            sys.argv = sys_argv

    def test_tamper_segment_digest(self):
        lines = (PACKET / "segments.txt").read_text().splitlines()
        bad = lines[1].split()
        bad[5] = "0" * 64
        self.assertNotEqual(" ".join(bad), lines[1])
        # the recorded digest must equal the binary digest (checked in
        # test_segments_match_binary); a zeroed digest never matches
        data = NODE.read_bytes()
        off = int(lines[1].split()[4], 16)
        length = int(lines[1].split()[3])
        self.assertNotEqual(hashlib.sha256(data[off:off + length]).hexdigest(),
                            "0" * 64)


if __name__ == "__main__":
    unittest.main()
