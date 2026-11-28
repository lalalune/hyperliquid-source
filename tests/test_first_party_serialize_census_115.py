import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-node115-first-party-serialize-census"
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(PACKET))

import byte_progress  # noqa: E402
import census  # noqa: E402
import verify_packets  # noqa: E402


class FirstPartySerializeCensus115Test(unittest.TestCase):
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
        self.assertEqual(s["total_windows"], 158)
        self.assertEqual(s["total_bytes"], 68370)
        self.assertEqual(s["components_matched"], 10)
        self.assertEqual(census.run_self_tests(data), 4)

    def test_all_records_strict_first_party_and_anchored(self) -> None:
        data = json.loads((PACKET / "records.json").read_text())
        for r in data["records"]:
            self.assertIn("hl_node115_serialize_census", r["symbol"])
            self.assertIn("Serialize", r["symbol"])
            self.assertNotIn("drop_in_place", r["symbol"])
            self.assertIn(r["anchor_mode"], ("rodata", "inline_ascii", "rodata+inline_ascii"))
            self.assertGreaterEqual(len(r["authenticated_strings"]), min(r["expected_count"], 2))

    def test_dry_run_byte_progress_load_coverage(self) -> None:
        data = json.loads((PACKET / "records.json").read_text())
        reg = json.loads((ROOT / "research/byte-windows.json").read_text())
        existing_ids = {w["id"] for w in reg["windows"]}
        extra = []
        for idx, r in enumerate(data["records"]):
            wid = f"{census.WINDOW_PREFIX}{idx:04d}"
            if wid in existing_ids:
                continue
            extra.append(
                {
                    "id": wid,
                    "target": "node115",
                    "component": r["component"],
                    "start": r["start"],
                    "end": r["end"],
                    "source_crate": "hl_node115_serialize_census",
                    "source_symbol": r["symbol"],
                    "work_item": "RE-001-node115-first-party-serialize-census",
                    "raw_equal": r["raw_equal"],
                }
            )
        # Verify strict zero-overlap against existing node115 windows in byte-windows.json
        existing_ivs = [
            (int(w["start"]), int(w["end"]), w["id"])
            for w in reg["windows"]
            if w.get("target") == "node115" and not w.get("id", "").startswith(census.WINDOW_PREFIX)
        ]
        for w in extra:
            s, e = w["start"], w["end"]
            for a, b, eid in existing_ivs:
                self.assertFalse(s < b and a < e, f"overlap {w['id']} vs {eid}")
        self.assertGreater(len(extra), 0)

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
        self.assertIn("PASS: RE-001-node115-first-party-serialize-census", res.stdout)
        self.assertIn("negative_controls=4/4", res.stdout)


if __name__ == "__main__":
    unittest.main()
