"""Verify 219 node #115 Stream E2 first-party compiled-byte FDE matches (5,475 B across 6 components)."""
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-007-node115-stream-e2-byte-matches"
VERIFY_PY = PACKET / "verify.py"


def _load_verifier():
    spec = importlib.util.spec_from_file_location("verify_stream_e2_byte_matches_115", VERIFY_PY)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class StreamE2ByteMatchesNode115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_verifier()
        cls.binary_bytes = cls.mod.BINARY_PATH.read_bytes()
        cls.obj_bytes, cls.rustc_ver = cls.mod.compile_object()
        cls.records = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))

    def test_219_windows_live_rustc_rebuild_and_negative_controls(self) -> None:
        self.mod.verify_records(self.records, self.binary_bytes, self.obj_bytes, self.rustc_ver)
        summary = self.records["summary"]
        self.assertEqual(summary["total_windows"], 219)
        self.assertEqual(summary["total_bytes"], 5475)
        self.assertEqual(
            set(summary["by_component"].keys()),
            {"vaults", "action-wire", "risk", "exchange", "dex-registry", "l1-shared"},
        )
        caught = self.mod.run_negative_controls(
            self.records, self.binary_bytes, self.obj_bytes, self.rustc_ver
        )
        self.assertEqual(caught, 4)

    def test_manifest_integrity(self) -> None:
        manifest = PACKET / "MANIFEST.sha256"
        lines = [ln.strip() for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 4)
        for line in lines:
            want, rel = line.split("  ", 1)
            got = hashlib.sha256((PACKET / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want)


if __name__ == "__main__":
    unittest.main()
