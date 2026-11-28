"""Run the capture inspector on actual temporary files and hardlinks."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from inspect_archive import inspect, layout

DAY = "20261025"
H = 1196590000


class PeriodicCaptureTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.snapshot, self.status, self.rolling = layout(self.root, DAY, H)
        for path in (self.snapshot, self.status, self.rolling):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.payload = b"offline synthetic checkpoint\x00"
        self.snapshot.write_bytes(self.payload)
        self.digest = hashlib.sha256(self.payload).hexdigest()

    def test_empty_status_and_rolling_link_are_independent(self):
        self.status.touch()
        os.link(self.snapshot, self.rolling)
        report = inspect(self.root, DAY, H, self.digest)
        self.assertEqual(report["status_marker"], "empty_regular_file")
        self.assertEqual(report["rolling_relation"], "same_opened_file_identity")
        self.assertNotEqual(self.status.stat().st_ino, self.snapshot.stat().st_ino)
        self.assertEqual(report["snapshot"], f"data/periodic_abci_states/{DAY}/{H}.rmp")
        self.assertEqual(report["status"], f"data/periodic_abci_state_statuses/{DAY}/{H}")

        later = self.rolling.with_name("later.rmp")
        later.write_bytes(b"next synthetic checkpoint")
        later.replace(self.rolling)
        report = inspect(self.root, DAY, H, self.digest)
        self.assertEqual(report["rolling_relation"], "different_file_identity")
        self.assertEqual(report["status_marker"], "empty_regular_file")

    def test_missing_and_nonregular_are_observed_separately(self):
        report = inspect(self.root, DAY, H, self.digest)
        self.assertEqual(report["status_marker"], "absent")
        self.assertEqual(report["rolling_relation"], "absent")
        self.status.mkdir()
        self.rolling.mkdir()
        report = inspect(self.root, DAY, H, self.digest)
        self.assertEqual(report["status_marker"], "nonregular")
        self.assertEqual(report["rolling_relation"], "nonregular")

    def test_existing_nonempty_status_is_not_a_root_reference(self):
        self.status.write_text("external note")
        self.rolling.write_bytes(self.payload)
        report = inspect(self.root, DAY, H, self.digest)
        self.assertEqual(report["status_marker"], "nonempty_regular_file")
        self.assertEqual(report["rolling_relation"], "different_file_identity")

    def test_cli_projects_a_pinned_local_capture(self):
        command = [
            sys.executable, "-B", str(Path(__file__).with_name("inspect_archive.py")),
            str(self.root), DAY, str(H), "--sha256", self.digest,
        ]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)["snapshot_sha256"], self.digest)

    def test_periodic_identity_and_coordinate_controls(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            inspect(self.root, DAY, H, "0" * 64)
        with self.assertRaises(ValueError):
            layout(self.root, "20261325", H)
        with self.assertRaises(ValueError):
            layout(self.root, "../escape", H)
        with self.assertRaises(ValueError):
            layout(self.root, DAY, 1 << 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
