"""Tests for the node #115 RE-011 small-input ordering packet checker."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools" / "foundation_small_input_ordering.py"
PACKET = ROOT / "research" / "work-items" / "RE-011-node115-small-input-ordering"
EVIDENCE = PACKET / "evidence.json"


def run_checker(evidence_path):
    return subprocess.run(
        [sys.executable, "-B", str(CHECKER), "--root", str(ROOT), "--evidence", str(evidence_path)],
        capture_output=True,
        text=True,
    )


def load_evidence():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


class SmallInputOrderingPacketTest(unittest.TestCase):
    def test_saved_packet_is_re_derived(self):
        proc = run_checker(EVIDENCE)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS", proc.stdout)

    def test_missing_evidence_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_checker(Path(tmp) / "absent.json")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("evidence file is missing", proc.stderr)

    def test_window_digest_drift_fails(self):
        evidence = load_evidence()
        evidence["window"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            proc = run_checker(path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("window digest", proc.stderr)

    def test_comparison_opcode_drift_fails(self):
        evidence = load_evidence()
        raw = bytearray(bytes.fromhex(evidence["comparison"]["cmp"]["bytes_hex"]))
        raw[-1] ^= 0xFF
        evidence["comparison"]["cmp"]["bytes_hex"] = bytes(raw).hex()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            proc = run_checker(path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("cmp site", proc.stderr)

    def test_stride_immediate_drift_fails(self):
        evidence = load_evidence()
        site = evidence["stride"]["sites"][0]
        raw = bytearray(bytes.fromhex(site["bytes_hex"]))
        raw[-1] = 0x21
        site["bytes_hex"] = bytes(raw).hex()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            proc = run_checker(path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("stride site", proc.stderr)

    def test_audited_probes_accept_real_bytes(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("foundation_small_input_ordering", CHECKER)
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        data = (ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        segments = checker.load_segments(data)
        window = checker.read_va(data, segments, 0x26CE540, 0x26CE5EC - 0x26CE540)
        derived = checker.inspect_comparison(window, 0x26CE540, 0x26CE592, 0x26CE599, 0x26CE59D)
        self.assertEqual(derived["jae_target"], 0x26CE57E)
        self.assertLess(derived["jae_target"], 0x26CE59D)
        self.assertEqual(checker.inspect_back_edge(window, 0x26CE540, 0x26CE5E1), 0x26CE5B0)
        self.assertEqual(checker.decode_stride_shift(bytes.fromhex("48c1e605")), 32)
        self.assertEqual(checker.decode_stride_shift(bytes.fromhex("48c1e205")), 32)
        self.assertEqual(checker.validate_stride(window, 0x26CE540, [{"va": 0x26CE557, "bytes_hex": "48c1e605"}]), [0x26CE557])

    def test_model_relation_drift_fails(self):
        evidence = load_evidence()
        evidence["model"]["pairs"][0][-1] = 99
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            proc = run_checker(path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("model relation", proc.stderr)


if __name__ == "__main__":
    unittest.main()
