import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import re008_heartbeat_classification115 as subject


class HeartbeatClassificationEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (
            not subject.TARGET.is_file()
            or subject.TARGET.stat().st_size != subject.TARGET_SIZE
        ):
            raise unittest.SkipTest("materialized node115 required")
        cls.data = subject.TARGET.read_bytes()

    def test_authenticated_target_windows_and_cases(self):
        metrics = subject.verify(self.data)
        self.assertEqual(metrics["body_bytes"], 1194)
        self.assertEqual(metrics["selected_windows"], 4)
        self.assertEqual(metrics["cases"], 1025)

    def test_wrong_target_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "wrong node115 digest"):
            subject.verify_binary(self.data, "0" * 64)

    def test_changed_body_is_rejected_after_digest_update(self):
        mutant = bytearray(self.data)
        mutant[subject.BODY_OFFSET + 0x100] ^= 1
        mutant = bytes(mutant)
        with self.assertRaisesRegex(ValueError, "wrong heartbeat FDE body"):
            subject.verify_binary(mutant, hashlib.sha256(mutant).hexdigest())

    def test_changed_native_window_is_rejected(self):
        mutant = bytearray(self.data)
        mutant[subject.WINDOWS[1][1]] ^= 1
        with self.assertRaisesRegex(ValueError, "wrong selected window"):
            subject.verify_windows(bytes(mutant))

    def test_changed_vector_is_rejected(self):
        text = subject.CASES.read_text(encoding="ascii")
        lines = text.splitlines()
        lines[1] = lines[1].replace("\tmissing\t", "\tratio\t", 1)
        with self.assertRaisesRegex(ValueError, "case mismatch"):
            subject.verify_cases("\n".join(lines) + "\n")


if __name__ == "__main__":
    unittest.main()
