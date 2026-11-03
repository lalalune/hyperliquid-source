"""Physical evidence controls for the Node115 signed reader family."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import node115_signed_scalar as native


class SignedScalarEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = ROOT / "artifacts/node/115/hl-node"
        cls.raw = cls.binary.read_bytes()
        cls.sections, cls.read = native.image(cls.raw)

    def test_complete_native_family_and_independent_rows(self):
        result = native.verify(self.binary)
        self.assertEqual(result, {"functions": 4, "bytes": 1044, "rows": 298,
                                  "rawEqualRows": True, "targetExecuted": False})

    def test_deleted_or_duplicated_instruction_is_rejected(self):
        start, size, _ = native.FUNCTIONS[0]
        rows = native.capstone_rows((native.PACKET / f"{start:x}.capstone.tsv").read_text())
        for broken in (rows[:8] + rows[9:], rows[:8] + rows[7:], rows[:-1]):
            with self.assertRaises(ValueError):
                native.verify_rows(type(self).read(start, size), start, broken)

    def test_target_instruction_byte_or_address_substitution_is_rejected(self):
        start, size, _ = native.FUNCTIONS[0]
        rows = native.capstone_rows((native.PACKET / f"{start:x}.capstone.tsv").read_text())
        address, raw = rows[8]
        for substituted in ((address + 1, raw), (address, bytes([raw[0] ^ 1]) + raw[1:])):
            broken = rows[:8] + [substituted] + rows[9:]
            with self.assertRaises(ValueError):
                native.verify_rows(type(self).read(start, size), start, broken)

    def test_gnu_tail_loss_cannot_satisfy_the_extent(self):
        start, size, _ = native.FUNCTIONS[2]
        rows = native.gnu_rows((native.PACKET / f"{start:x}.objdump").read_text())
        with self.assertRaises(ValueError):
            native.verify_rows(type(self).read(start, size), start, rows[:-1])

    def test_zero_length_rows_cannot_hide_a_gap(self):
        start, size, _ = native.FUNCTIONS[3]
        rows = native.capstone_rows((native.PACKET / f"{start:x}.capstone.tsv").read_text())
        with self.assertRaises(ValueError):
            native.verify_rows(type(self).read(start, size), start, [(start, b"")] + rows)


if __name__ == "__main__":
    unittest.main()
