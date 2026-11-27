"""Tests for RE-015-node115-constants-thinlto-byte-matches."""

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
    / "RE-015-node115-constants-thinlto-byte-matches"
)
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
BYTE_WINDOWS_PATH = REPO_ROOT / "research" / "byte-windows.json"
SIBLING_PACKETS = [
    REPO_ROOT / "research" / "work-items" / "RE-015-node115-constants-gate-closure" / "records.json",
    REPO_ROOT / "research" / "work-items" / "RE-015-node115-stream-f-byte-matches" / "records.json",
]


def _load_verify():
    spec = importlib.util.spec_from_file_location(
        "re015_constants_thinlto_byte_matches_verify", PACKET_DIR / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(BINARY_PATH.exists(), "node #115 binary required")
class ConstantsThinLtoByteMatches115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_verify()
        cls.data = BINARY_PATH.read_bytes()
        cls.records = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))
        cls.bodies = (PACKET_DIR / "bodies.bin").read_bytes()

    def test_committed_bodies_match_node115_and_cgu_totals(self) -> None:
        self.mod.verify_records(self.records, self.data, self.bodies, rebuild=False)
        s = self.records["summary"]
        self.assertEqual(s["windows"], 22)
        self.assertEqual(s["total_bytes"], 14354)
        self.assertEqual(s["relocation_qualified_windows"], 22)
        self.assertEqual(s["cgu_total_matched_fdes"], 36)
        self.assertEqual(s["cgu_total_fdes"], 40)
        self.assertEqual(s["cgu_total_matched_bytes"], 22195)
        self.assertEqual(s["cgu_total_bytes"], 23050)
        self.assertEqual(s["by_attribution"]["first_party_logic"]["windows"], 5)
        self.assertEqual(s["by_attribution"]["first_party_logic"]["bytes"], 5231)
        self.assertEqual(s["by_attribution"]["cgu_monomorphized_serde_drop"]["windows"], 17)
        self.assertEqual(s["by_attribution"]["cgu_monomorphized_serde_drop"]["bytes"], 9123)

    def test_windows_disjoint_from_dependencies_and_sibling_packets(self) -> None:
        ours = [(int(w["start"], 16), int(w["end"], 16)) for w in self.records["windows"]]
        ours_sorted = sorted(ours)
        for (s1, e1), (s2, e2) in zip(ours_sorted, ours_sorted[1:]):
            self.assertLessEqual(e1, s2, f"internal overlap: {hex(s1)}..{hex(e1)} vs {hex(s2)}..{hex(e2)}")

        # Wave-4 consolidation-safe: forbid ANY overlap with dependency windows and ANY partial overlap with first-party
        if BYTE_WINDOWS_PATH.exists():
            bw = json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
            for w in bw.get("windows", []):
                ws = int(w["start"], 16) if isinstance(w["start"], str) else int(w["start"])
                we = int(w["end"], 16) if isinstance(w["end"], str) else int(w["end"])
                is_dep = "dependency" in w
                for os_, oe_ in ours:
                    if os_ < we and ws < oe_:
                        if is_dep or (os_, oe_) != (ws, we):
                            self.fail(
                                f"overlap with byte-windows.json ({'dep' if is_dep else 'partial fp'}): "
                                f"{hex(os_)}..{hex(oe_)} vs {hex(ws)}..{hex(we)}"
                            )

        # Strictly disjoint from sibling Stream F packets
        for sib in SIBLING_PACKETS:
            if sib.exists():
                doc = json.loads(sib.read_text(encoding="utf-8"))
                for w in doc.get("windows", []):
                    ws = int(w["start"], 16)
                    we = int(w["end"], 16)
                    for os_, oe_ in ours:
                        self.assertFalse(
                            os_ < we and ws < oe_,
                            f"overlap with {sib.parent.name}: {hex(os_)}..{hex(oe_)} vs {hex(ws)}..{hex(we)}",
                        )

    def test_all_four_negative_controls_are_rejected(self) -> None:
        rejected = self.mod.run_negative_controls(self.records, self.data, self.bodies)
        self.assertEqual(rejected, 4)


if __name__ == "__main__":
    unittest.main()
