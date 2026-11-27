#!/usr/bin/env python3
"""Verify RE-008-node115-staking-rewards-and-decay packet and node #115 binary anchors."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research" / "work-items" / "RE-008-node115-staking-rewards-and-decay"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"


def _load_verify():
    spec = importlib.util.spec_from_file_location("re008_staking_rewards_verify", VERIFY_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestNode115StakingRewardsAndDecay(unittest.TestCase):
    def test_verify_packet_and_negative_controls(self) -> None:
        mod = _load_verify()
        data = mod.BINARY_PATH.read_bytes()
        records = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        mod.verify_records(records, data)
        neg = mod.run_negative_controls(records, data)
        self.assertEqual(neg, 4)

        summary = records["summary"]
        self.assertEqual(summary["functions"], 6)
        self.assertEqual(summary["total_function_bytes"], 14_054)
        self.assertEqual(summary["rodata_f64_anchors"], 8)
        self.assertEqual(summary["rodata_str_anchors"], 3)
        self.assertEqual(summary["instruction_windows"], 9)

    def test_f64_constants_and_emission_curve(self) -> None:
        records = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        by_name = {r["name"]: r for r in records["rodata_f64_anchors"]}
        self.assertEqual(by_name["seconds_per_year_365_25d"]["value"], 31_557_600.0)
        self.assertEqual(by_name["emission_base_factor"]["value"], 0.015)
        self.assertEqual(by_name["emission_quadratic_coeff"]["value"], -0.5)
        self.assertEqual(by_name["commission_bps_scale"]["value"], 0.0001)
        self.assertEqual(by_name["reward_fraction_ceiling"]["value"], 1.01)
        self.assertEqual(by_name["staking_decay_factor"]["value"], 0.99)


if __name__ == "__main__":
    unittest.main()
