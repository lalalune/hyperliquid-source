"""Live rustc 1.95.0 compiled-byte verification tests for RE-012 Stream C FDE matches."""

import hashlib
import pathlib
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
PACKET_DIR = REPO / "research" / "work-items" / "RE-012-node115-stream-c-byte-matches"
MANIFEST_PATH = PACKET_DIR / "MANIFEST.sha256"

sys.path.insert(0, str(PACKET_DIR))
import verify as stream_c_verify  # noqa: E402


class TestStreamCByteMatches115(unittest.TestCase):
    def test_live_rustc_rebuild_and_negative_controls(self) -> None:
        summary = stream_c_verify.verify_all(run_self_test=True)
        self.assertEqual(summary["windows"], 34)
        self.assertEqual(summary["bytes"], 1182)
        self.assertEqual(summary["by_component"]["serialization"]["windows"], 2)
        self.assertEqual(summary["by_component"]["serialization"]["bytes"], 91)
        self.assertEqual(summary["by_component"]["transport"]["windows"], 3)
        self.assertEqual(summary["by_component"]["transport"]["bytes"], 75)
        self.assertEqual(summary["by_component"]["node-runtime"]["windows"], 29)
        self.assertEqual(summary["by_component"]["node-runtime"]["bytes"], 1016)

    def test_manifest_sha256_integrity(self) -> None:
        lines = [ln.strip() for ln in MANIFEST_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 4)
        seen = set()
        for line in lines:
            expected_hash, rel_name = line.split("  ", 1)
            seen.add(rel_name)
            actual = hashlib.sha256((PACKET_DIR / rel_name).read_bytes()).hexdigest()
            self.assertEqual(actual, expected_hash, f"checksum mismatch for {rel_name}")
        self.assertEqual(seen, {"README.md", "lib.rs", "records.json", "verify.py"})


if __name__ == "__main__":
    unittest.main()
