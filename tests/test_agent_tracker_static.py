import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import agent_tracker_static as ats

PACKET = ROOT / "research" / "work-items" / "agent-tracker-94"
BINARY = ROOT / ats.BINARY_REL


class AgentTrackerStaticTests(unittest.TestCase):
    def test_binary_digest(self):
        self.assertTrue(BINARY.exists())
        data = BINARY.read_bytes()
        ats.check_digest(data)
        with self.assertRaises(ats.EvidenceError):
            ats.check_digest(b"corrupt")

    def test_fde_extents_and_digests(self):
        data = BINARY.read_bytes()
        analysis = ats.analyse(data)
        self.assertEqual(len(analysis["fdes"]), 3)
        total_bytes = sum(f["bytes"] for f in analysis["fdes"])
        self.assertEqual(total_bytes, 4032)
        self.assertEqual(analysis["fdes"][0]["bytes"], 1728)
        self.assertEqual(analysis["fdes"][1]["bytes"], 768)
        self.assertEqual(analysis["fdes"][2]["bytes"], 1536)

    def test_panic_records(self):
        data = BINARY.read_bytes()
        analysis = ats.analyse(data)
        records = analysis["source_records"]
        self.assertEqual(len(records), 1)
        self.assertIn("0x56eb400", records)
        self.assertEqual(records["0x56eb400"]["line"], 138)
        self.assertEqual(records["0x56eb400"]["col"], 48)
        self.assertTrue(records["0x56eb400"]["path"].endswith("agent_tracker.rs"))

    def test_controls(self):
        data = BINARY.read_bytes()
        analysis = ats.analyse(data)
        controls = analysis["controls"]
        self.assertEqual(len(controls), len(ats.CONTROLS))
        for va, op in ats.CONTROLS.items():
            self.assertIn(hex(va), controls)
            self.assertEqual(controls[hex(va)], op)

    def test_negative_control_mutation(self):
        data = BINARY.read_bytes()
        orig = ats.CONTROLS[0x3422314]
        try:
            ats.CONTROLS[0x3422314] = "909090909090"
            with self.assertRaises(ats.EvidenceError):
                ats.analyse(data)
        finally:
            ats.CONTROLS[0x3422314] = orig

    def test_bypass_addresses(self):
        data = BINARY.read_bytes()
        analysis = ats.analyse(data)
        bypasses = analysis["bypass_addresses"]
        self.assertEqual(len(bypasses), 3)
        self.assertEqual(bypasses[0]["address"], "0x677d831aef5328190852e24f13c46cac05f984e7")
        self.assertEqual(bypasses[1]["address"], "0x3c83a5cae32a05e88ca6a0350edb540194851a76")
        self.assertEqual(bypasses[2]["address"], "0x4dbf394da4b348b88e8090d22051af83e4cbaef4")

    def test_capacity_model(self):
        # Normal addresses follow 2 * tier + 3
        normal_addr = "0x1111111111111111111111111111111111111111"
        self.assertEqual(ats.extra_agent_capacity(0, normal_addr), 3)
        self.assertEqual(ats.extra_agent_capacity(1, normal_addr), 5)
        self.assertEqual(ats.extra_agent_capacity(2, normal_addr), 7)
        self.assertEqual(ats.extra_agent_capacity(5, normal_addr), 13)

        # Bypass addresses bypass the dynamic limit
        bypass_addr = "0x677d831aef5328190852e24f13c46cac05f984e7"
        self.assertEqual(ats.extra_agent_capacity(0, bypass_addr), 1000000)

    def test_agent_name_validation(self):
        self.assertFalse(ats.validate_agent_name(""))
        self.assertTrue(ats.validate_agent_name("bot-1"))
        self.assertTrue(ats.validate_agent_name("a" * 32))
        self.assertFalse(ats.validate_agent_name("a" * 33))

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
            ats.generate_packet(tmp_path, BINARY)
            manifest_orig = (PACKET / "MANIFEST.sha256").read_bytes()
            manifest_new = (tmp_path / "MANIFEST.sha256").read_bytes()
            self.assertEqual(manifest_orig, manifest_new)


if __name__ == "__main__":
    unittest.main()
