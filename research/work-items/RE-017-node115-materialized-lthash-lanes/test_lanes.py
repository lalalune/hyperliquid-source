"""Check the archived-cache versus compact-state comparator on offline fixtures."""

from hashlib import sha256
import json
from pathlib import Path
from struct import pack, pack_into
import subprocess
import sys
import tempfile
import unittest

from compare_lanes import compare

H = 1196590000
NAMES = ("accounts_hash", "contracts_hash", "storage_hash")


class MaterializedLtHashTests(unittest.TestCase):
    def setUp(self):
        image = bytearray(b"\x91" * 0x42C8)
        pack_into("<Q", image, 0x28, H)
        digests = {}
        for index, name in enumerate(NAMES):
            record = bytes([index + 1]) * 0x800 + pack("<QQ", index, index + 42)
            offset = 0x1200 + index * 0x908
            image[offset:offset + len(record)] = record
            digests[name] = sha256(record).hexdigest()
        self.image = image
        self.digests = digests

    def run_compare(self):
        return compare(self.image, sha256(self.image).hexdigest(), H, self.digests)

    def test_all_named_records_match(self):
        report = self.run_compare()
        self.assertTrue(report["matches"])
        self.assertEqual(report["height"], H)
        self.assertEqual([report["records"][name]["offset"] for name in NAMES],
                         [0x1200, 0x1B08, 0x2410])

    def test_pointer_descriptor_bytes_are_outside_selected_records(self):
        self.image[0x1108] ^= 1
        self.image[0x1B07] ^= 1
        self.assertTrue(self.run_compare()["matches"])

    def test_a_different_counter_changes_only_its_lane(self):
        self.image[0x1B08 + 0x808] ^= 1
        report = self.run_compare()
        self.assertFalse(report["matches"])
        self.assertEqual([row["matches"] for row in report["records"].values()], [True, False, True])

    def test_identity_height_and_length_are_independent_controls(self):
        digest = sha256(self.image).hexdigest()
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            compare(self.image, "0" * 64, H, self.digests)
        with self.assertRaisesRegex(ValueError, "height"):
            compare(self.image, digest, H + 1, self.digests)
        with self.assertRaisesRegex(ValueError, "0x42c8"):
            compare(self.image[:-1], digest, H, self.digests)
        with self.assertRaisesRegex(ValueError, "digest"):
            compare(self.image, digest, H, {"accounts_hash": "0" * 64})

    def test_cli_compares_a_real_local_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "compact-state.bin"
            path.write_bytes(self.image)
            command = [sys.executable, "-B", str(Path(__file__).with_name("compare_lanes.py")),
                       str(path), "--state-sha256", sha256(self.image).hexdigest(),
                       "--height", str(H)]
            for name in NAMES:
                command.extend(["--" + name.split("_")[0] + "-sha256", self.digests[name]])
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertTrue(json.loads(result.stdout)["matches"])
            command[-1] = "0" * 64
            result = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(result.stdout)["matches"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
