"""Frozen native snapshots/active fields; fresh ELF checks live in the packet."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "research/work-items/RE-008-qc-fd-group-short-94"
SPEC = importlib.util.spec_from_file_location("fd_group_short_native", HERE / "verify.py")
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)


class Snapshot:
    def __init__(self):
        self.bytes = {}
        prior = HERE.parent / "RE-008-qc-fd-group-success-94/native.gnu.txt"
        for path in (prior, HERE / "native.gnu.txt"):
            for m in N.RX.finditer(path.read_text()):
                va, data = int(m[1], 16), bytes.fromhex(m[2])
                for i, value in enumerate(data):
                    if va + i in self.bytes:
                        assert self.bytes[va + i] == value
                    self.bytes[va + i] = value
        freeze = json.loads((HERE / "PRE-RUST-FREEZE.json").read_text())
        table = freeze["Reader_table"]
        self.bytes.update({int(table["va"], 16) + i: value for i, value in enumerate(bytes.fromhex(table["hex"]))})

    def read(self, va, count):
        return bytes(self.bytes[va + i] for i in range(count))


class QcFdGroupShort94(unittest.TestCase):
    def test_frozen_native_bodies_and36_expectations(self):
        frozen = (HERE / "PRE-RUST-FREEZE.json").read_bytes()
        self.assertEqual(hashlib.sha256(frozen).hexdigest(), N.FREEZE_SHA)
        freeze, image = json.loads(frozen), Snapshot()
        for f in freeze["functions"][:3]:
            a, b = int(f["start"], 16), int(f["end"], 16)
            self.assertEqual(hashlib.sha256(image.read(a, b - a)).hexdigest(), f["body_sha256"])
        for name, pin in freeze["fixtures"].items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), pin["sha256"])

    def test_all_positions_short_payloads_and_eof_are_distinct(self):
        freeze = json.loads((HERE / "PRE-RUST-FREEZE.json").read_text())
        params = N.parameters(Snapshot())
        inputs, expected = N.rows(HERE / "inputs.tsv"), N.rows(HERE / "expected.tsv")
        self.assertEqual(len(inputs), 36)
        for case, wanted in zip(inputs, expected, strict=True):
            actual, trace = N.relation(params, case)
            self.assertEqual({key: actual[key] for key in wanted}, wanted, case["id"])
            self.assertEqual(actual["wrapper_attempts"], freeze["case_domains"][case["id"]]["failed_position"])
            self.assertEqual(trace[-1], int(case["charge"]) + 32)
            self.assertTrue(actual["row_error_route"])

    def test_ten_site_controls_match_frozen_native_distinctions(self):
        freeze = json.loads((HERE / "PRE-RUST-FREEZE.json").read_text())
        inputs = N.rows(HERE / "inputs.tsv")
        for edit in freeze["native_controls"]:
            image = Snapshot()
            image.bytes[int(edit["va"], 16)] = int(edit["after"], 16)
            case = next(c for c in inputs if c["id"] == edit["witness"])
            changed, _ = N.relation(N.parameters(image), case)
            original, _ = N.relation(N.parameters(Snapshot()), case)
            self.assertNotEqual(changed, original)
            N.check_control_prediction(edit, changed)


if __name__ == "__main__":
    unittest.main()
