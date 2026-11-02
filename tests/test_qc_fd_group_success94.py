"""Fast frozen-native checks; fresh ELF authentication is the packet verifier."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "research/work-items/RE-008-qc-fd-group-success-94"
SPEC = importlib.util.spec_from_file_location("qc_fd_group_native", HERE / "verify.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


class Snapshot:
    def __init__(self):
        self.bytes = {}
        for match in NATIVE.RX.finditer((HERE / "native.gnu.txt").read_text()):
            address, code = int(match[1], 16), bytes.fromhex(match[2])
            self.bytes.update({address + i: byte for i, byte in enumerate(code)})
        table = json.loads((HERE / "PRE-RUST-FREEZE.json").read_text())["wrapper_table"]
        self.bytes.update({int(table["va"], 16) + i: byte for i, byte in enumerate(bytes.fromhex(table["hex"]))})

    def read(self, address, size):
        return bytes(self.bytes[address + i] for i in range(size))


class QcFdGroupSuccess94(unittest.TestCase):
    def test_native_snapshot_and_pre_rust_fixtures_are_pinned(self):
        frozen = (HERE / "PRE-RUST-FREEZE.json").read_bytes()
        self.assertEqual(hashlib.sha256(frozen).hexdigest(), NATIVE.FREEZE_SHA)
        freeze, snapshot = json.loads(frozen), Snapshot()
        for function in freeze["functions"][:2]:
            start, end = int(function["start"], 16), int(function["end"], 16)
            self.assertEqual(hashlib.sha256(snapshot.read(start, end - start)).hexdigest(), function["body_sha256"])
        for name, pin in freeze["fixtures"].items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), pin["sha256"])

    def test_qualified_charge_width_order_and_all40_bytes(self):
        parameters = NATIVE.parameters(Snapshot())
        for row, expected in zip(NATIVE.rows(HERE / "inputs.tsv"), NATIVE.rows(HERE / "expected.tsv"), strict=True):
            actual, writes = NATIVE.relation(parameters, row)
            self.assertEqual(actual, expected, row["id"])
            self.assertEqual(writes, [int(row["charge"]) + n for n in (32, 24, 32, 24, 32, 24, 32, 24, 32)])
        self.assertEqual(parameters["destinations"], [8, 16, 24, 32])
        self.assertEqual(parameters["wire_width"], 9)

    def test_six_normal_domain_site_changes_have_counterexamples(self):
        freeze = json.loads((HERE / "PRE-RUST-FREEZE.json").read_text())
        inputs, expected = NATIVE.rows(HERE / "inputs.tsv"), NATIVE.rows(HERE / "expected.tsv")
        for mutation in freeze["native_controls"]:
            changed = Snapshot()
            changed.bytes[int(mutation["va"], 16)] = int(mutation["after"], 16)
            parameters = NATIVE.parameters(changed)
            self.assertTrue(any(NATIVE.relation(parameters, row)[0] != wanted for row, wanted in zip(inputs, expected, strict=True)), mutation["name"])


if __name__ == "__main__":
    unittest.main()
