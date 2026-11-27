#!/usr/bin/env python3
"""Verify RE-008-node115-consensus-staking-byte-matches (193 first-party compiled-byte FDEs)."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research" / "work-items" / "RE-008-node115-consensus-staking-byte-matches"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"


def _load_verify():
    spec = importlib.util.spec_from_file_location("re008_byte_matches_verify", VERIFY_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestConsensusStakingByteMatches115(unittest.TestCase):
    def test_live_rebuild_and_negative_controls(self) -> None:
        mod = _load_verify()
        hl_data = mod.BINARY_PATH.read_bytes()
        records = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        mod.verify_records(records, hl_data, rebuild=True)
        neg = mod.run_negative_controls(records, hl_data)
        self.assertEqual(neg, 4)

        summary = records["summary"]
        self.assertEqual(summary["windows"], 193)
        self.assertEqual(summary["total_bytes"], 4825)
        self.assertEqual(summary["staking_windows"], 162)
        self.assertEqual(summary["staking_bytes"], 4050)
        self.assertEqual(summary["consensus_windows"], 31)
        self.assertEqual(summary["consensus_bytes"], 775)

    def test_disjoint_from_byte_windows_and_other_stream_packets(self) -> None:
        records = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        ours = [
            (int(w["start_va"], 16), int(w["end_va"], 16), w["label"])
            for w in records["windows"]
        ]
        # Zero overlap against dependency windows and zero partial overlap against first-party windows
        # in research/byte-windows.json (exact (s, e) first-party consolidation match is allowed).
        bw = json.loads((REPO_ROOT / "research" / "byte-windows.json").read_text(encoding="utf-8"))
        reg = [
            (int(w["start"]), int(w["end"]), w.get("id", "?"), "dependency" in w)
            for w in bw["windows"]
        ]
        for s, e, lbl in ours:
            for rs, re_, rid, is_dep in reg:
                if s < re_ and rs < e:
                    if is_dep or (s, e) != (rs, re_):
                        self.fail(f"{lbl} overlaps research/byte-windows.json entry {rid}")

        # Strictly disjoint from every peer *byte-matches* packet (handling both end_va/end and size_bytes/size)
        checked_peers = 0
        for other_rec in sorted((REPO_ROOT / "research" / "work-items").glob("*byte-matches*/records.json")):
            if other_rec.parent == PACKET_DIR:
                continue
            other = json.loads(other_rec.read_text(encoding="utf-8"))
            peer_windows = other.get("windows", [])
            for ow in peer_windows:
                os_ = ow.get("start_va", ow.get("start"))
                if isinstance(os_, str):
                    os_ = int(os_, 16)
                oe_ = ow.get("end_va", ow.get("end"))
                if isinstance(oe_, str):
                    oe_ = int(oe_, 16)
                if oe_ is None and os_ is not None:
                    sz = ow.get("size_bytes", ow.get("size"))
                    if sz is not None:
                        oe_ = os_ + int(sz)
                self.assertIsNotNone(os_, f"missing start in {other_rec}")
                self.assertIsNotNone(oe_, f"missing end/size in {other_rec}")
                checked_peers += 1
                for s, e, lbl in ours:
                    self.assertFalse(
                        s < oe_ and os_ < e,
                        f"{lbl} overlaps {other_rec.parent.name} (0x{os_:x}..0x{oe_:x})",
                    )
        self.assertGreater(checked_peers, 0)


if __name__ == "__main__":
    unittest.main()
