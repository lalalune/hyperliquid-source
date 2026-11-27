import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET_DIR = (
    REPO
    / "research"
    / "work-items"
    / "RE-009-node115-abci-closure"
)


class TestAbciClosure115(unittest.TestCase):
    def test_verify_self_test(self) -> None:
        res = subprocess.run(
            [sys.executable, str(PACKET_DIR / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
        self.assertIn("4/4 l1/src/abci files, 57/57 Locations, 41/41 FDEs (89230 B)", res.stdout)
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
