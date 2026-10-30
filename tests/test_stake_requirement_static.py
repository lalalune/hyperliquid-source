import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import stake_requirement_static as srs

PACKET = ROOT / "research" / "work-items" / "stake-requirement-94"
BINARY = ROOT / srs.BINARY_REL


class StakeRequirementStaticTests(unittest.TestCase):
    def test_binary_digest(self):
        self.assertTrue(BINARY.exists())
        data = BINARY.read_bytes()
        srs.check_digest(data)
        with self.assertRaises(srs.EvidenceError):
            srs.check_digest(b"corrupt")

    def test_analysis_fdes(self):
        data = BINARY.read_bytes()
        analysis = srs.analyse(data)
        self.assertEqual(len(analysis["fdes"]), 4)
        total_bytes = sum(f["bytes"] for f in analysis["fdes"])
        self.assertEqual(total_bytes, 1936)

    def test_multiplier_matrix(self):
        data = BINARY.read_bytes()
        analysis = srs.analyse(data)
        self.assertEqual(analysis["table_values"], srs.TABLE_VALUES)
        self.assertEqual(len(srs.TABLE_VALUES), 4)
        for row in srs.TABLE_VALUES:
            self.assertEqual(len(row), 4)

    def test_panic_records(self):
        data = BINARY.read_bytes()
        analysis = srs.analyse(data)
        self.assertEqual(analysis["source_path"], srs.SOURCE_PATH)
        for va, info in srs.PANIC_LOCATIONS.items():
            self.assertEqual(info["line"], 5)
            self.assertEqual(info["col"], 62)

    def test_manifest_verification(self):
        manifest_path = PACKET / "MANIFEST.sha256"
        self.assertTrue(manifest_path.exists())
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(lines), 4)
        for line in lines:
            digest, rel_path = line.split("  ")
            target = PACKET / rel_path
            self.assertTrue(target.is_file(), f"Target missing: {target}")
            data = target.read_bytes()
            self.assertFalse(b"\r" in data, f"CRLF in {target}")
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)

    def test_packet_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            srs.generate_packet(tmp_path, BINARY)
            manifest_orig = (PACKET / "MANIFEST.sha256").read_bytes()
            manifest_new = (tmp_path / "MANIFEST.sha256").read_bytes()
            self.assertEqual(manifest_orig, manifest_new)


if __name__ == "__main__":
    unittest.main()
