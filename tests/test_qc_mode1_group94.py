"""Pre-source mode1 group algebra and comparator controls; no target execution."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-008-qc-mode1-group-94"


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, PACKET / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NATIVE = load("mode1_static", "verify.py")
RUST = load("mode1_rust_comparator", "verify_rust.py")


class Mode1NativeDerivedContract(unittest.TestCase):
    def test128_frozen_states_include_budget_priority_and_preserved_memory(self):
        inputs, expected = NATIVE.verify_vectors()
        counts = [0, 0, 0]
        for i, e in zip(inputs, expected, strict=True):
            if e[5] == "0":
                counts[0] += 1
            elif e[6] == "0":
                counts[1] += 1
            else:
                counts[2] += 1
                self.assertEqual(e[2], "0")
                self.assertEqual(e[7], "-")
                self.assertEqual(e[10], "-")
                before = bytes.fromhex(i["group_before_hex"])
                after = bytes.fromhex(e[12])
                self.assertEqual(after[:9], b"\x01" + bytes(7) + b"\x02")
                self.assertEqual(after[9:], before[9:])
        self.assertEqual(counts, [41, 63, 24])

    def test_guard_boundaries_keep_distinct_charge_effects(self):
        inputs, expected = NATIVE.verify_vectors()
        rows = {i["id"]: (i, e) for i, e in zip(inputs, expected, strict=True)}
        self.assertEqual(rows["edge-maxcharge-eof"][1][1], str((1 << 64) - 1))
        self.assertEqual(rows["edge-maxcharge-eof"][1][6:8], ["0", "1"])
        for name in ("overflow-1-eof", "overflow-1-invalid-prefix"):
            i, e = rows[name]
            self.assertEqual(e[1], i["charge"])
        for name in ("limit-1-eof", "limit-1-invalid-prefix"):
            self.assertEqual(rows[name][1][1], "32")
            self.assertEqual(rows[name][1][6:8], ["2", "-"])

    def test_api_only_refusal_cannot_satisfy_any_native_control(self):
        outside = RUST.read_result(b"id\t0\t0\t0\t-\t-\t-\t-\t-\t-\t-\t-\t-")
        for control in NATIVE.freeze()["native_controls"]:
            with self.assertRaises(ValueError, msg=control["name"]):
                RUST.verify_control(control, outside)

    def test_success_cannot_omit_values_or_memory(self):
        for tail in (b"-\t-", b"00" * 32 + b"\t-"):
            with self.assertRaises(ValueError):
                RUST.read_result(b"id\t32\t4\t0\t-\t0\t-\t-\t-\t-\t-\t" + tail)


if __name__ == "__main__":
    unittest.main()
