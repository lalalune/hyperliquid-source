import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import re009_db_hub_lookup115 as subject


class DbHubLookupEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (
            not subject.TARGET.is_file()
            or subject.TARGET.stat().st_size != subject.TARGET_SIZE
        ):
            raise unittest.SkipTest("materialized node115 required")
        cls.data = subject.TARGET.read_bytes()

    def test_authenticated_target_body_windows_and_cases(self):
        metrics = subject.verify(self.data)
        self.assertEqual(metrics["body_bytes"], 841)
        self.assertEqual(metrics["selected_windows"], 3)
        self.assertEqual(metrics["cases"], 1284)

    def test_wrong_target_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "wrong node115 digest"):
            subject.verify_binary(self.data, "0" * 64)

    def test_changed_body_is_rejected_after_digest_update(self):
        mutant = bytearray(self.data)
        mutant[subject.BODY_FILE_OFFSET + 0x200] ^= 1
        mutant = bytes(mutant)
        with self.assertRaisesRegex(ValueError, "wrong selected FDE body"):
            subject.verify_binary(mutant, hashlib.sha256(mutant).hexdigest())

    def test_changed_native_window_is_rejected(self):
        mutant = bytearray(self.data)
        mutant[subject.WINDOWS[1][1]] ^= 1
        with self.assertRaisesRegex(ValueError, "wrong selected window"):
            subject.verify_windows(bytes(mutant))

    def test_malformed_or_changed_cases_are_rejected(self):
        text = subject.CASES.read_text(encoding="ascii")
        lines = text.splitlines()
        lines[1] = lines[1].replace("\tmissing\t", "\tfound\t0", 1)
        with self.assertRaisesRegex(ValueError, "case mismatch"):
            subject.verify_cases("\n".join(lines) + "\n")
        with self.assertRaisesRegex(ValueError, "unknown case"):
            subject.verify_cases(
                "\n".join([lines[0], lines[1].replace("empty", "bad", 1)]) + "\n"
            )


if __name__ == "__main__":
    unittest.main()
