"""Tests for RE-015-node115-constants-first-party-100pct-byte-matches."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = (
    REPO_ROOT
    / "research"
    / "work-items"
    / "RE-015-node115-constants-first-party-100pct-byte-matches"
)
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
BYTE_WINDOWS_PATH = REPO_ROOT / "research" / "byte-windows.json"
WORK_ITEMS_DIR = REPO_ROOT / "research" / "work-items"


def _load_verify():
    spec = importlib.util.spec_from_file_location(
        "re015_constants_fp100_verify", PACKET_DIR / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parse_int(val) -> int | None:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 16) if val.startswith(("0x", "0X")) else int(val)
        except ValueError:
            return None
    return None


@unittest.skipUnless(BINARY_PATH.exists(), "node #115 binary required")
class ConstantsFirstParty100PctByteMatches115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_verify()
        cls.data = BINARY_PATH.read_bytes()
        cls.records = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))
        cls.bodies = (PACKET_DIR / "bodies.bin").read_bytes()

    def test_committed_bodies_and_first_party_100pct_cgu_totals(self) -> None:
        self.mod.verify_records(self.records, self.data, self.bodies, rebuild=False)
        s = self.records["summary"]
        self.assertEqual(s["windows"], 2)
        self.assertEqual(s["total_bytes"], 682)
        self.assertEqual(s["relocation_qualified_windows"], 2)
        self.assertEqual(s["first_party_cgu_matched_fdes"], 12)
        self.assertEqual(s["first_party_cgu_total_fdes"], 12)
        self.assertEqual(s["first_party_cgu_matched_bytes"], 12753)
        self.assertEqual(s["first_party_cgu_total_bytes"], 12753)
        self.assertEqual(s["cgu_total_matched_fdes"], 38)
        self.assertEqual(s["cgu_total_fdes"], 40)
        self.assertEqual(s["cgu_total_matched_bytes"], 22877)
        self.assertEqual(s["cgu_total_bytes"], 23050)
        self.assertEqual(s["global_constants_locations_verified"], 5)
        self.assertFalse(s["identity_gate_satisfied"])
        # Strict first-party attribution check (no stdlib/dependency windows)
        for row in self.records["windows"]:
            self.assertEqual(row["component"], "constants")
            self.assertEqual(row["attribution"], "first_party_logic")
            self.assertIn("16global_constants", row["symbol"])

    def test_windows_strictly_disjoint_from_byte_windows_and_all_sibling_packets(self) -> None:
        ours = [(int(w["start"], 16), int(w["end"], 16)) for w in self.records["windows"]]
        ours_sorted = sorted(ours)
        for (s1, e1), (s2, e2) in zip(ours_sorted, ours_sorted[1:]):
            self.assertLessEqual(e1, s2, f"internal overlap: {hex(s1)}..{hex(e1)} vs {hex(s2)}..{hex(e2)}")

        # Wave-consolidation-safe check against research/byte-windows.json
        if BYTE_WINDOWS_PATH.exists():
            bw = json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
            for w in bw.get("windows", []):
                ws = _parse_int(w.get("start"))
                we = _parse_int(w.get("end"))
                if ws is None or we is None:
                    continue
                is_dep = "dependency" in w
                for os_, oe_ in ours:
                    if os_ < we and ws < oe_:
                        if is_dep or (os_, oe_) != (ws, we):
                            self.fail(
                                f"overlap with byte-windows.json ({'dep' if is_dep else 'partial fp'}): "
                                f"{hex(os_)}..{hex(oe_)} vs {hex(ws)}..{hex(we)}"
                            )

        # Strictly disjoint from ALL sibling byte-match packets (checking both start/end and start_va/end_va)
        for p in sorted(WORK_ITEMS_DIR.glob("*/records.json")):
            if p.parent == PACKET_DIR:
                continue
            name = p.parent.name
            if not any(
                tag in name
                for tag in ("byte-matches", "thinlto", "gate-closure", "100pct", "census", "consolidation")
            ):
                continue
            doc = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                continue
            for key in ("windows", "records", "matches", "entries"):
                arr = doc.get(key)
                if not isinstance(arr, list):
                    continue
                for row in arr:
                    if not isinstance(row, dict):
                        continue
                    ws = _parse_int(row.get("start") if "start" in row else row.get("start_va"))
                    we = _parse_int(row.get("end") if "end" in row else row.get("end_va"))
                    if ws is None or we is None:
                        continue
                    for os_, oe_ in ours:
                        self.assertFalse(
                            os_ < we and ws < oe_,
                            f"overlap with {name}: {hex(os_)}..{hex(oe_)} vs {hex(ws)}..{hex(we)}",
                        )

    def test_all_four_negative_controls_are_rejected(self) -> None:
        rejected = self.mod.run_negative_controls(self.records, self.data, self.bodies)
        self.assertEqual(rejected, 4)


if __name__ == "__main__":
    unittest.main()
