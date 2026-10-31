import hashlib
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import action_delayer_static as ads

PACKET = ROOT / "research" / "work-items" / "action-delayer-94"
BINARY = ROOT / ads.BINARY_REL


class ActionDelayerStaticTests(unittest.TestCase):
    def test_binary_digest(self):
        self.assertTrue(BINARY.exists())
        data = BINARY.read_bytes()
        ads.check_digest(data)
        with self.assertRaises(ads.EvidenceError):
            ads.check_digest(b"corrupt")

    def test_fde_extents_and_digests(self):
        data = BINARY.read_bytes()
        analysis = ads.analyse(data)
        self.assertEqual(len(analysis["fdes"]), 4)
        total_bytes = sum(f["bytes"] for f in analysis["fdes"])
        self.assertEqual(total_bytes, 3136)
        self.assertEqual(analysis["fdes"][0]["bytes"], 528)
        self.assertEqual(analysis["fdes"][1]["bytes"], 1664)
        self.assertEqual(analysis["fdes"][2]["bytes"], 384)
        self.assertEqual(analysis["fdes"][3]["bytes"], 560)

    def test_panic_records(self):
        data = BINARY.read_bytes()
        analysis = ads.analyse(data)
        records = analysis["source_records"]
        self.assertEqual(len(records), 4)

        # 1. action_delayer.rs:246:73
        self.assertIn("0x570d828", records)
        self.assertEqual(records["0x570d828"]["line"], 246)
        self.assertEqual(records["0x570d828"]["col"], 73)
        self.assertTrue(records["0x570d828"]["path"].endswith("action_delayer.rs"))

        # 2 & 3. duration.rs
        self.assertIn("0x566ab58", records)
        self.assertEqual(records["0x566ab58"]["line"], 112)
        self.assertEqual(records["0x566ab58"]["col"], 13)

        self.assertIn("0x566ae58", records)
        self.assertEqual(records["0x566ae58"]["line"], 124)
        self.assertEqual(records["0x566ae58"]["col"], 13)

        # 4. serde ser.rs
        self.assertIn("0x570fef0", records)
        self.assertEqual(records["0x570fef0"]["line"], 2004)
        self.assertEqual(records["0x570fef0"]["col"], 9)

    def test_controls(self):
        data = BINARY.read_bytes()
        analysis = ads.analyse(data)
        controls = analysis["controls"]
        self.assertEqual(len(controls), len(ads.CONTROLS))
        for va, op in ads.CONTROLS.items():
            self.assertIn(hex(va), controls)
            self.assertEqual(controls[hex(va)], op)

    def test_negative_control_mutation(self):
        data = BINARY.read_bytes()
        orig = ads.CONTROLS[0x3930221]
        try:
            ads.CONTROLS[0x3930221] = "909090909090909090"
            with self.assertRaises(ads.EvidenceError):
                ads.analyse(data)
        finally:
            ads.CONTROLS[0x3930221] = orig

    def test_constants(self):
        self.assertAlmostEqual(ads.MIN_ACTION_DELAY_SECONDS, 0.76)
        self.assertEqual(ads.VTY_REFERENCE_NOTIONAL, 10000.0)
        self.assertEqual(ads.FRONTEND_ACTION_ID_START, 10000)
        self.assertEqual(ads.FRONTEND_ACTION_ID_END, 110000)
        self.assertEqual(ads.BROADCASTER_ACTION_ID_START, 100000000)
        self.assertAlmostEqual(ads.SPECIAL_CURVE_MULTIPLIER, 1.8)
        self.assertAlmostEqual(ads.DEFAULT_CURVE_MULTIPLIER, 1.3)
        self.assertAlmostEqual(ads.SHORT_DELAY_MULTIPLIER, 0.2)
        self.assertAlmostEqual(ads.STANDARD_DELAY_MULTIPLIER, 0.65)

    def test_deterministic_delay_seconds_model(self):
        # 1. Mode 2 with special action kind (e.g. 11054)
        delay_mode2_special = ads.deterministic_delay_seconds(2, 11054, 10000.0)
        # raw_weight = 1.0^-1.5 * 0.125 = 0.125
        # clamped = 0.125
        # unscaled = 0.125 * 1.8 + 0.76 = 0.225 + 0.76 = 0.985
        # delay = 0.985 * 0.65 = 0.64025
        self.assertAlmostEqual(delay_mode2_special, 0.985 * 0.65)

        # 2. Mode 2 with action kind 0
        delay_mode2_zero = ads.deterministic_delay_seconds(2, 0, 10000.0)
        # raw_weight = 1.0^-3.0 / 12.0 = 1/12
        # unscaled = (1/12) * 1.8 + 0.76 = 0.15 + 0.76 = 0.91
        # delay = 0.91 * 0.65 = 0.5915
        self.assertAlmostEqual(delay_mode2_zero, 0.91 * 0.65)

        # 3. Default action kind with frontend action id (short multiplier 0.2)
        delay_frontend = ads.deterministic_delay_seconds(1, 20000, 10000.0)
        # raw_weight = 1.0^-4.0 / 20.0 = 0.05
        # unscaled = 0.05 * 1.3 + 0.76 = 0.065 + 0.76 = 0.825
        # delay = 0.825 * 0.2 = 0.165
        self.assertAlmostEqual(delay_frontend, 0.825 * 0.2)

        # 4. Default action kind with broadcaster action id (short multiplier 0.2)
        delay_broadcaster = ads.deterministic_delay_seconds(1, 100000001, 10000.0)
        self.assertAlmostEqual(delay_broadcaster, 0.825 * 0.2)

        # 5. Invalid inputs raise EvidenceError
        with self.assertRaises(ads.EvidenceError):
            ads.deterministic_delay_seconds(1, 0, 0.0)
        with self.assertRaises(ads.EvidenceError):
            ads.deterministic_delay_seconds(1, 0, -100.0)
        with self.assertRaises(ads.EvidenceError):
            ads.deterministic_delay_seconds(1, 0, float("nan"))

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
            ads.generate_packet(tmp_path, BINARY)
            manifest_orig = (PACKET / "MANIFEST.sha256").read_bytes()
            manifest_new = (tmp_path / "MANIFEST.sha256").read_bytes()
            self.assertEqual(manifest_orig, manifest_new)


if __name__ == "__main__":
    unittest.main()
