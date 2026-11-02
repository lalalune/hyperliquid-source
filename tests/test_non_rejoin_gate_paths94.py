"""Unit tests for the RE-004 non-rejoin sentinel-gate packet.

Run from the repository root:
    python3 -m unittest discover -s tests -p 'test_non_rejoin_gate_paths94.py'
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402
import non_rejoin_gate_paths94 as gen  # noqa: E402

PACKET = ROOT / "research/work-items/RE-004-non-rejoin-gate-paths-94"
BINARY = ROOT / "artifacts/node/94/hl-node"
GENERATED = ["evidence.json", "paths.tsv", "segments.txt", "cases.tsv"]


def run_generator(out_dir, env_extra=None):
    import os
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools/non_rejoin_gate_paths94.py"),
         "--binary", str(BINARY), "--out", str(out_dir)],
        cwd=ROOT, env=env, capture_output=True, text=True)
    return proc


class TestNonRejoinGatePaths(unittest.TestCase):
    def test_regeneration_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "regen"
            proc = run_generator(out)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            for name in GENERATED:
                self.assertEqual(
                    (out / name).read_bytes(), (PACKET / name).read_bytes(),
                    f"{name} differs from packet")

    def test_cross_env_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "a", Path(tmp) / "b"
            pa = run_generator(a, {"PYTHONHASHSEED": "1", "TZ": "UTC"})
            pb = run_generator(b, {"PYTHONHASHSEED": "42", "TZ": "Asia/Seoul"})
            self.assertEqual(pa.returncode, 0, pa.stderr)
            self.assertEqual(pb.returncode, 0, pb.stderr)
            for name in GENERATED:
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes(),
                                 f"{name} not deterministic across env")

    def test_packet_shape_and_counts(self):
        evidence = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(evidence["nonrejoin_total"], 13)
        self.assertEqual(evidence["segments_total"], 9)
        self.assertEqual(evidence["cases"], 13)
        self.assertEqual(evidence["partition"],
                         {"same_callee": 3, "twin_B_clone": 4, "twin_shape": 2,
                          "attributed": 4})
        self.assertFalse(evidence["vectors_zero_distinguishes_any"])
        self.assertEqual(len(evidence["gates"]), 13)
        paths = (PACKET / "paths.tsv").read_text().splitlines()
        self.assertEqual(len(paths), 14)  # header + 13
        self.assertTrue(paths[0].startswith("fde\t"))
        segments = (PACKET / "segments.txt").read_text().splitlines()
        self.assertEqual(len(segments), 9)
        cases = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(len(cases), 14)  # header + 13
        # Every segmented gate installs the full [obj+0x0..0x40] on the
        # non-match path and the shorter [obj+0x0..0x38] on match.
        for row in paths[1:]:
            cols = row.split("\t")
            if cols[7] in ("new", "instance", "classified"):
                self.assertTrue(cols[16].endswith("+0x0..0x40]"), row)
                self.assertTrue(cols[17].endswith("+0x0..0x38]"), row)
                self.assertEqual(cols[18], "false")
        # Partition arithmetic on the file itself.
        from collections import Counter
        disp = Counter(row.split("\t")[7] for row in paths[1:])
        self.assertEqual(disp["new"], 3)
        self.assertEqual(disp["instance"], 4)
        self.assertEqual(disp["classified"], 2)
        self.assertEqual(disp["attributed"], 4)

    def test_manifest(self):
        proc = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                              cwd=PACKET, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_census_independent(self):
        """Re-derive the census with the generator's own byte-level scan
        and check it against the packet (no capstone involved)."""
        data = BINARY.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), gen.SHA256)
        secs, _ = elf_index.unwind_index(data)
        cands = gen.disp32_scan(data, secs)
        self.assertEqual(len(cands), 94)
        for disp_va in cands:
            off = next(s["offset"] + (disp_va - 4) - s["address"]
                       for s in secs if s["type"] != 8 and s["address"] <= disp_va - 4 < s["address"] + s["size"])
            prefix = data[off:off + 4]
            self.assertEqual(prefix[0], 0x66)
            self.assertEqual(prefix[1], 0x0F)
            self.assertEqual(prefix[2], 0x74)
            self.assertEqual(prefix[3] & 0xC7, 0x05)

    def test_anchor_tamper_fails_census(self):
        """Flipping one compare's disp32 byte in memory must change the
        census (anchor control)."""
        data = bytearray(BINARY.read_bytes())
        secs, _ = elf_index.unwind_index(bytes(data))
        cands = gen.disp32_scan(bytes(data), secs)
        first_disp = sorted(cands)[0]
        off = next(s["offset"] + first_disp - s["address"]
                   for s in secs if s["type"] != 8 and s["address"] <= first_disp < s["address"] + s["size"])
        data[off] ^= 0xFF
        cands2 = gen.disp32_scan(bytes(data), secs)
        self.assertNotEqual(len(cands2), 94)

    def test_segment_tamper_changes_digest(self):
        """Flipping one byte inside a recorded segment must change its
        digest (segment control)."""
        data = bytearray(BINARY.read_bytes())
        secs, _ = elf_index.unwind_index(bytes(data))
        seg = next(g["segment"] for g in gen.GATES if g["fde"] == "0x4e6fd50")
        start = int(seg["start"], 16)
        off = gen.va_to_offset(secs, start)
        before = hashlib.sha256(bytes(data[off:off + 80])).hexdigest()
        data[off] ^= 0xFF
        after = hashlib.sha256(bytes(data[off:off + 80])).hexdigest()
        self.assertNotEqual(before, after)

    def test_trio_both_path_callee_equality(self):
        """The same-callee trio's match-path call target must equal its
        non-match first-call target (the packet's core claim)."""
        for g in gen.GATES:
            if g["disposition"] == "new":
                self.assertIsNotNone(g["match_call"])
                self.assertEqual(g["match_call"]["target"],
                                 g["first_call"]["target"])


if __name__ == "__main__":
    unittest.main()
