import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import re004_pdi_range115 as subject


class PdiRangeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (
            not subject.TARGET.is_file()
            or subject.TARGET.stat().st_size != subject.TARGET_SIZE
        ):
            raise unittest.SkipTest("materialized node115 required")
        cls.data = subject.TARGET.read_bytes()

    def test_authenticated_target_records_windows_and_cases(self):
        metrics = subject.verify(self.data)
        self.assertEqual(metrics["body_bytes"], 2897)
        self.assertEqual(metrics["selected_windows"], 3)
        self.assertEqual(metrics["cases"], 49)

    def test_wrong_target_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "wrong node115 digest"):
            subject.verify_binary(self.data, "0" * 64)

    def test_changed_body_is_rejected_after_digest_update(self):
        mutant = bytearray(self.data)
        mutant[subject.BODIES[0][1] + 0x40] ^= 1
        mutant = bytes(mutant)
        with self.assertRaisesRegex(ValueError, "wrong range FDE body"):
            subject.verify_binary(mutant, hashlib.sha256(mutant).hexdigest())

    def test_changed_native_window_is_rejected(self):
        mutant = bytearray(self.data)
        mutant[subject.WINDOWS[1][1]] ^= 1
        with self.assertRaisesRegex(ValueError, "wrong selected window"):
            subject.verify_windows(bytes(mutant))

    def test_changed_vector_is_rejected(self):
        text = subject.CASES.read_text(encoding="ascii")
        lines = text.splitlines()
        lines[10] = lines[10].replace("\tok\t", "\tadd\t", 1)
        with self.assertRaisesRegex(ValueError, "case mismatch"):
            subject.verify_cases("\n".join(lines) + "\n")


if __name__ == "__main__":
    unittest.main()
