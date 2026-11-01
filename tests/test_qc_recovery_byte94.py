"""Static native binding and frozen mathematical field cases; no captured execution."""
import csv
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-008-qc-recovery-byte-94"
spec = importlib.util.spec_from_file_location("qc_recovery_byte94", PACKET / "evidence.py")
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)


class QcRecoveryByte94(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = e.Image((ROOT / "artifacts/node/94/hl-node").read_bytes())
        cls.params = e.derive(cls.image)
        cls.frozen = json.loads((PACKET / "observed/records.json").read_text())

    def test_native_parameters_and_complete_bytes(self):
        self.assertEqual(self.params, self.frozen["parameters"])
        _, fdes = e.eh_frame_records(self.image.data)
        for record in self.frozen["functions"]:
            start, end = int(record["start"], 16), int(record["end"], 16)
            with self.subTest(name=record["name"]):
                self.assertEqual([(f["end"], hex(f["fde"])) for f in fdes if f["start"] == start],
                                 [(end, record["fde"]["va"])])
                self.assertEqual(e.sha(self.image.read(start, end-start)), record["body_sha256"])
        rows = e.decode_rows((PACKET / "observed/native.gnu.txt").read_text())
        self.assertEqual(len(rows), self.frozen["summary"]["instructions"])
        for va, raw, _ in rows:
            self.assertEqual(self.image.read(va, len(raw)), raw)

    def test_frozen_boundary_table(self):
        with (PACKET / "boundaries.csv").open() as file:
            for row in csv.DictReader(file):
                with self.subTest(name=row["name"]):
                    actual = e.project_field(self.params, *(int(row[k]) for k in ("mode", "charge", "limit", "remaining", "byte")))
                    for key in ("status", "charge_after", "consumed", "kind", "value"):
                        expected = row[key] if key == "status" else None if row[key] == "-" else int(row[key])
                        self.assertEqual(actual[key], expected)
                    self.assertEqual(actual["pointer_after"], 0x1000 + actual["consumed"])
                    self.assertEqual(actual["remaining_after"], int(row["remaining"]) - actual["consumed"])

    def test_charge_and_cursor_write_order_and_error_kinds(self):
        cases = [
            ((1, 2**64-1, 2**64-1, 1, 9), 2, []),
            ((1, 2**64-1, 2**64-1, 0, 9), 2, []),
            ((1, 3, 3, 1, 9), 2, [["charge", 4]]),
            ((1, 3, 3, 0, 9), 2, [["charge", 4]]),
            ((1, 2, 3, 0, 9), 0, [["charge", 3]]),
            ((0, 7, 0, 0, 9), 0, []),
            ((1, 2, 3, 2, 9), None, [["charge", 3], ["pointer", 0x1001], ["remaining", 1]]),
        ]
        for inputs, kind, writes in cases:
            with self.subTest(inputs=inputs):
                actual = e.project_field(self.params, *inputs)
                self.assertEqual(actual["kind"], kind)
                self.assertEqual(actual["state_writes"], writes)

    def test_all_byte_values_have_the_same_single_byte_projection(self):
        for mode in (0, 1):
            for remaining in (1, 2):
                for byte in range(256):
                    actual = e.project_field(self.params, mode, 2, 3, remaining, byte)
                    self.assertEqual((actual["result_tag"], actual["value"], actual["consumed"]), (0, byte, 1))
                    self.assertEqual(actual["charge_after"], 2 + mode)
                    self.assertEqual(actual["state_writes"][-2:], [["pointer", 0x1001], ["remaining", remaining-1]])

    def test_native_width_and_charge_alias_counterexamples_below_digest(self):
        image = self.image
        class Overlay:
            def __init__(self, at, byte): self.at, self.byte = at, byte
            def read(self, va, size):
                raw = bytearray(image.read(va, size))
                if va <= self.at < va + size: raw[self.at-va] = self.byte
                return bytes(raw)
        with self.assertRaisesRegex(ValueError, "field width/cursor direction"):
            e.derive(Overlay(0x4C7E536, 0xB7))
        with self.assertRaisesRegex(ValueError, "charge state-field agreement"):
            e.derive(Overlay(0x4C7E51A, 0x18))

    def test_success_bypass_is_rejected(self):
        rows = e.decode_rows((PACKET / "observed/native.gnu.txt").read_text())
        rows = [(a, raw, asm) for a, raw, asm in rows if 0x4C7E340 <= a < 0x4C7E60D]
        e.check_graph(rows)
        mutant = [(va, raw[:2] + struct.pack("<i", e.SUCCESS-va-6) if va == 0x4C7E52B else raw, asm) for va, raw, asm in rows]
        with self.assertRaisesRegex(ValueError, "success bypasses"):
            e.check_graph(mutant)


if __name__ == "__main__":
    unittest.main()
