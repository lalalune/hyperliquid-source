import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-node115-first-party-serialize-wave2-census"
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(PACKET))

import census  # noqa: E402
import verify_packets  # noqa: E402


class FirstPartySerializeWave2Census115Test(unittest.TestCase):
    def test_manifest_and_forbid_unsafe(self) -> None:
        manifest = PACKET / "MANIFEST.sha256"
        entries = verify_packets.parse_manifest(manifest)
        self.assertGreaterEqual(len(entries), 8)
        for expected, rel in entries:
            p = PACKET / rel
            self.assertTrue(p.is_file(), f"missing manifest entry {rel}")
            self.assertEqual(census.sha(p.read_bytes()), expected, f"digest mismatch for {rel}")
        src = (PACKET / "harness/src/main.rs").read_text()
        self.assertIn("#![forbid(unsafe_code)]", src)
        self.assertNotIn("unsafe ", src)

    def test_verify_and_negative_controls(self) -> None:
        data = census.verify_committed()
        s = data["summary"]
        self.assertEqual(s["total_windows"], 190)
        self.assertEqual(s["total_bytes"], 87914)
        self.assertEqual(s["components_matched"], 16)
        self.assertEqual(census.run_self_tests(data), 4)

    def test_all_records_strict_first_party_and_rodata_anchored(self) -> None:
        data = json.loads((PACKET / "records.json").read_text())
        for r in data["records"]:
            self.assertIn("hl_node115_serialize_wave2_census", r["symbol"])
            self.assertIn("Serialize", r["symbol"])
            self.assertNotIn("drop_in_place", r["symbol"])
            self.assertEqual(r["anchor_mode"], "rodata")
            self.assertGreaterEqual(len(r["authenticated_strings"]), min(r["expected_count"], 2))

    def test_zero_overlap_against_byte_windows(self) -> None:
        data = json.loads((PACKET / "records.json").read_text())
        reg = json.loads((ROOT / "research/byte-windows.json").read_text())
        existing_ivs = [
            (int(w["start"]), int(w["end"]), w["id"])
            for w in reg["windows"]
            if w.get("target") == "node115" and not w.get("id", "").startswith(census.WINDOW_PREFIX)
        ]
        for idx, r in enumerate(data["records"]):
            s, e = r["start"], r["end"]
            for a, b, eid in existing_ivs:
                self.assertFalse(s < b and a < e, f"overlap node115-fp-ser2-{idx:04d} vs {eid}")

    def test_cli_verify_self_test(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        res = subprocess.run(
            [sys.executable, str(PACKET / "census.py"), "--self-test"],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("PASS: RE-001-node115-first-party-serialize-wave2-census", res.stdout)
        self.assertIn("negative_controls=4/4", res.stdout)


if __name__ == "__main__":
    unittest.main()
