import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET_DIR = ROOT / "research" / "work-items" / "RE-004-node115-stream-e1-byte-matches"
VERIFY_PY = PACKET_DIR / "verify.py"
MANIFEST_PATH = PACKET_DIR / "MANIFEST.sha256"


class TestStreamE1ByteMatches115(unittest.TestCase):
    def test_manifest_covers_all_packet_files(self) -> None:
        entries = {}
        for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            digest, rel = line.split(None, 1)
            entries[rel] = digest
        self.assertEqual(set(entries), {"README.md", "lib.rs", "records.json", "verify.py"})
        for rel, expected in entries.items():
            actual = hashlib.sha256((PACKET_DIR / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, f"manifest mismatch for {rel}")

    def test_live_rustc_compiled_byte_self_test(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(VERIFY_PY), "--self-test"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("PASS:", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)


if __name__ == "__main__":
    unittest.main()
