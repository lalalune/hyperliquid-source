"""Unit tests for the RE-004 sentinel-gate family packet.

Run from the repository root:
    python3 -m unittest discover -s tests -p 'test_sentinel_gate_family94.py'
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
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402
import sentinel_gate_family94 as gen  # noqa: E402

PACKET = ROOT / "research/work-items/RE-004-sentinel-gate-family-94"
BINARY = ROOT / "artifacts/node/94/hl-node"
GENERATED = ["evidence.json", "gates.tsv", "cases.tsv", "windows.txt"]


def run_generator(out_dir, env_extra=None):
    import os
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools/sentinel_gate_family94.py"),
         "--binary", str(BINARY), "--out", str(out_dir)],
        cwd=ROOT, env=env, capture_output=True, text=True)
    return proc


class TestSentinelGateFamily(unittest.TestCase):
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
        self.assertEqual(evidence["gates_total"], 47)
        self.assertEqual(evidence["fdes_total"], 46)
        self.assertEqual(evidence["cases"], 22)
        self.assertEqual(evidence["classes"], {"A": 42, "B": 3, "C": 2})
        self.assertEqual(evidence["polarity"], {"je": 36, "jne": 9, "setne": 2})
        self.assertEqual(len(evidence["windows"]), 46)
        gates = (PACKET / "gates.tsv").read_text().splitlines()
        self.assertEqual(len(gates), 48)  # header + 47
        self.assertTrue(gates[0].startswith("fde\t"))
        cases = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(len(cases), 23)  # header + 22
        windows = (PACKET / "windows.txt").read_text().splitlines()
        self.assertEqual(len(windows), 46)
        # Every gate row's FDE must have a window, and vice versa.
        gate_fdes = {row.split("\t")[0] for row in gates[1:]}
        win_fdes = {row.split("..")[0] for row in windows}
        self.assertEqual(gate_fdes, win_fdes)

    def test_manifest(self):
        proc = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                              cwd=PACKET, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_census_independent(self):
        """Re-derive the census with the generator's own byte-level scan
        and check it against gates.tsv (no capstone involved)."""
        data = BINARY.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), gen.SHA256)
        secs, _ = elf_index.unwind_index(data)
        cands = gen.disp32_scan(data, secs)
        self.assertEqual(len(cands), 94)
        # Every candidate's 3 preceding bytes must be 66 0f 74, modrm rip-relative.
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

    def test_non_anchor_tamper_keeps_census(self):
        """Flipping a byte far from any gate (in .text padding between two
        unrelated FDEs) must not change the census (non-anchor control)."""
        data = bytearray(BINARY.read_bytes())
        secs, _ = elf_index.unwind_index(bytes(data))
        # 0x1000 is inside .text but far from any recorded gate address.
        text = next(s for s in secs if s["name"] == ".text")
        off = text["offset"] + 0x1000
        data[off] ^= 0xFF
        cands = gen.disp32_scan(bytes(data), secs)
        self.assertEqual(len(cands), 94)

    def test_routing_model_consistent(self):
        """Case rows must agree with gate polarities: je gates branch on
        match, jne gates branch on non-match, setne gates yield 1 on
        non-match."""
        rows = (PACKET / "cases.tsv").read_text().splitlines()[1:]
        by_case = {r.split("\t")[0]: r.split("\t") for r in rows}
        self.assertEqual(by_case["A-je-match"][8], "branch taken: match path")
        self.assertEqual(by_case["A-je-nonmatch"][8], "fall-through: non-match path")
        self.assertEqual(by_case["A-jne-match"][8], "fall-through: match path")
        self.assertEqual(by_case["A-jne-nonmatch"][8], "branch taken: non-match path")
        self.assertEqual(by_case["C-setne-match"][8], "boolean 0")
        self.assertEqual(by_case["C-setne-nonmatch"][8], "boolean 1")
        self.assertEqual(by_case["VZ-nonmatch-vectors-zero"][8],
                         "rejoins match path difference check")
        self.assertEqual(by_case["DG-difference-zero"][8],
                         "counter test runs: sete r15b = (counter == 0)")


if __name__ == "__main__":
    unittest.main()
