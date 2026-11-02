"""Tests for the node #94 WAL replay gate model (tools/wal_replay_gate).

Target-grounded expectations come from
research/work-items/RE-001-wal-replay-gate-94/records.json: the gate
order, the unsigned comparison direction, the two verbatim report
texts and decision bytes, the pre-call contract, and the replay
caller's forwarded arguments. Boundary and corruption controls cover
the limit equality edge and the flag-over-sequence precedence.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from wal_replay_gate import (FLAG_MESSAGE, SEQUENCE_MESSAGE, Status,
                             build_detail, replay_gate)

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-wal-replay-gate-94"


class TestGate(unittest.TestCase):
    def test_flag_reports_decision_3_even_when_sequence_also_unwritten(self):
        out = Status()
        kind, result = replay_gate(out, 1, True, 10, 999, "b", "c", "d")
        self.assertEqual(kind, "report")
        self.assertIs(result, out)
        self.assertEqual(out.decision, 3)
        self.assertEqual(out.message, FLAG_MESSAGE)

    def test_sequence_report_decision_1_only_above_limit(self):
        for requested, expected in [(10, "replay"), (11, "report")]:
            out = Status()
            kind, _ = replay_gate(out, 0, False, 10, requested, "b", "c", "d")
            self.assertEqual(kind, expected, f"requested={requested}")
        out = Status()
        kind, _ = replay_gate(out, 0, False, 10, 11, "b", "c", "d")
        self.assertEqual(out.decision, 1)
        self.assertEqual(out.message, SEQUENCE_MESSAGE)

    def test_limit_equality_replays(self):
        out = Status()
        kind, call = replay_gate(out, 0, False, 42, 42, "b", "c", "d")
        self.assertEqual(kind, "replay")
        self.assertEqual(call["a"], 42)

    def test_pre_call_logged_only_when_object_present(self):
        log = []
        replay_gate(Status(), 0, True, 0, 0, "b", "c", "d", pre_call_log=log)
        self.assertEqual(log, [("vtable_slot_0xb0", 0x3C, 1)])
        log = []
        replay_gate(Status(), 0, False, 0, 0, "b", "c", "d", pre_call_log=log)
        self.assertEqual(log, [])

    def test_pre_call_runs_before_flag_report(self):
        log = []
        replay_gate(Status(), 1, True, 0, 999, "b", "c", "d", pre_call_log=log)
        self.assertEqual(len(log), 1)

    def test_replay_forwards_arguments_unchanged(self):
        out = Status()
        kind, call = replay_gate(out, 0, False, 100, 7, "b-obj", "c-obj",
                                 "d-obj")
        self.assertEqual(kind, "replay")
        self.assertIs(call["out"], out)
        self.assertEqual(call["ctx"], "context+0x1518")
        self.assertEqual((call["a"], call["b"], call["c"], call["d"]),
                         (7, "b-obj", "c-obj", "d-obj"))

    def test_builder_replaces_previous_message(self):
        out = Status(decision=9, message="stale")
        build_detail(out, 1, SEQUENCE_MESSAGE)
        self.assertEqual(out.decision, 1)
        self.assertEqual(out.message, SEQUENCE_MESSAGE)

    def test_report_texts_match_packet_records(self):
        records = json.loads((PACKET / "records.json").read_text())
        flag = records["phases_in_order"][1]["message"]
        seq = records["phases_in_order"][2]["report"]["message"]
        self.assertEqual(FLAG_MESSAGE, flag["text"])
        self.assertEqual(len(FLAG_MESSAGE), flag["length"])
        self.assertEqual(SEQUENCE_MESSAGE, seq["text"])
        self.assertEqual(len(SEQUENCE_MESSAGE), seq["length"])

    def test_packet_checker_passes(self):
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ALL CHECKS PASSED", proc.stdout)

    def test_corruption_control_rejects_tampered_manifest(self):
        # A packet whose manifest no longer matches must fail its own
        # checker; this guards the checker against vacuous passes.
        # The copy is laid out like the repo (work/ + research/) so
        # the copied checker resolves the real binary the same way.
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "work").mkdir()
            shutil.copy(ROOT / "work/hl-node-94.bin",
                        tmp / "work/hl-node-94.bin")
            dest = tmp / "research/work-items/RE-001-wal-replay-gate-94"
            shutil.copytree(PACKET, dest)
            (dest / "records.json").write_text(
                (dest / "records.json").read_text().replace(
                    "write-prepared", "write-preparex"))
            proc = subprocess.run(
                [sys.executable, str(dest / "verify.py")],
                cwd=tmp, capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("manifest", proc.stdout)


if __name__ == "__main__":
    unittest.main()
