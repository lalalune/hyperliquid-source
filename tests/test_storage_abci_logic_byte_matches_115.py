import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET_DIR = (
    REPO
    / "research"
    / "work-items"
    / "RE-009-node115-storage-abci-logic-byte-matches"
)


class TestStorageAbciLogicByteMatches115(unittest.TestCase):
    def test_verify_self_test(self) -> None:
        res = subprocess.run(
            [sys.executable, str(PACKET_DIR / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
        self.assertIn("7/7 relocation-qualified, 1404 B (1169 raw-equal, 0 100%-raw", res.stdout)
        self.assertIn("storage 5w/898B, abci 2w/506B", res.stdout)
        self.assertIn("4/4 negative controls rejected", res.stdout)

    def test_manifest_sha256(self) -> None:
        res = subprocess.run(
            ["sha256sum", "-c", "MANIFEST.sha256"],
            cwd=PACKET_DIR,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
