import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import re011_storage_key_suffix115 as subject


class StorageKeySuffixEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (
            not subject.TARGET.is_file()
            or subject.TARGET.stat().st_size != subject.TARGET_SIZE
        ):
            raise unittest.SkipTest("materialized node115 required")
        cls.data = subject.TARGET.read_bytes()

    def test_authenticated_target_and_frozen_vectors(self):
        metrics = subject.verify(self.data)
        self.assertEqual(metrics["body_bytes"], 411)
        self.assertEqual(metrics["selected_windows"], 3)
        self.assertEqual(metrics["key_vectors"], 258)

    def test_wrong_binary_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "wrong node115 digest"):
            subject.verify_binary(self.data, "0" * 64)

    def test_changed_body_is_rejected_after_digest_is_updated(self):
        mutant = bytearray(self.data)
        mutant[subject.BODY_FILE_OFFSET + 0x100] ^= 1
        mutant = bytes(mutant)
        with self.assertRaisesRegex(ValueError, "wrong selected FDE body digest"):
            subject.verify_binary(mutant, hashlib.sha256(mutant).hexdigest())

    def test_changed_selected_window_is_rejected(self):
        mutant = bytearray(self.data)
        mutant[subject.WINDOWS[0][1]] ^= 1
        with self.assertRaisesRegex(ValueError, "wrong selected window"):
            subject.verify_windows(bytes(mutant))

    def test_malformed_vector_fields_are_rejected(self):
        text = subject.VECTORS.read_text(encoding="utf-8")
        lines = text.splitlines()
        lines[1] = lines[1].replace("\t00010203", "\t0001020", 1)
        with self.assertRaisesRegex(ValueError, "malformed address"):
            subject.verify_vectors("\n".join(lines) + "\n")

    def test_duplicate_vector_case_is_rejected(self):
        text = subject.VECTORS.read_text(encoding="utf-8")
        lines = text.splitlines()
        lines[2] = lines[2].replace(lines[2].split("\t", 1)[0], lines[1].split("\t", 1)[0], 1)
        with self.assertRaisesRegex(ValueError, "duplicate key-vector case"):
            subject.verify_vectors("\n".join(lines) + "\n")


if __name__ == "__main__":
    unittest.main()
