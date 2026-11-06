import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import re010_display_name_decision115 as subject


class DisplayNameDecisionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (
            not subject.TARGET.is_file()
            or subject.TARGET.stat().st_size != subject.TARGET_SIZE
        ):
            raise unittest.SkipTest("materialized node115 required")
        cls.data = subject.TARGET.read_bytes()

    def test_authenticated_target_bodies_windows_and_vectors(self):
        metrics = subject.verify(self.data)
        self.assertEqual(metrics["body_bytes"], 1124)
        self.assertEqual(metrics["selected_windows"], 2)
        self.assertEqual(metrics["branch_vectors"], 14)

    def test_wrong_target_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "wrong node115 digest"):
            subject.verify_binary(self.data, "0" * 64)

    def test_changed_body_is_rejected_after_digest_update(self):
        mutant = bytearray(self.data)
        mutant[subject.CORE[0] + 0x100] ^= 1
        mutant = bytes(mutant)
        with self.assertRaisesRegex(ValueError, "wrong core FDE body"):
            subject.verify_binary(mutant, hashlib.sha256(mutant).hexdigest())

    def test_changed_window_is_rejected(self):
        mutant = bytearray(self.data)
        mutant[subject.WINDOWS[1][1]] ^= 1
        with self.assertRaisesRegex(ValueError, "wrong selected window"):
            subject.verify_windows(bytes(mutant))

    def test_changed_vector_is_rejected(self):
        text = subject.VECTORS.read_text(encoding="ascii")
        lines = text.splitlines()
        lines[2] = lines[2].replace("\tempty\t", "\tunique\t", 1)
        with self.assertRaisesRegex(ValueError, "branch-vector mismatch"):
            subject.verify_vectors("\n".join(lines) + "\n")


if __name__ == "__main__":
    unittest.main()
