"""Target-grounded replay and corruption controls for one TLS installer."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "tls_context_install", ROOT / "research/work-items/RE-001-node115-tls-context-install/check.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class TLSContextInstall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = CHECK.inspect()
        cls.windows = {int(row["va"], 16): bytes.fromhex(row["bytes"])
                       for row in cls.report["windows"]}

    def test_authenticated_native_windows_and_frame(self):
        self.assertEqual(self.report["target_sha256"], CHECK.SHA256)
        self.assertEqual(self.report["selected_windows"], 3)
        self.assertFalse(self.report["target_executed"])
        CHECK.check_windows(self.windows)
        CHECK.check_frame(self.report["frame"])

    def test_every_selected_byte_corruption_rejected(self):
        for va, value in self.windows.items():
            for index in range(len(value)):
                with self.subTest(va=hex(va), index=index):
                    changed = dict(self.windows)
                    changed[va] = value[:index] + bytes([value[index] ^ 1]) + value[index + 1:]
                    with self.assertRaisesRegex(ValueError, "instruction mismatch"):
                        CHECK.check_windows(changed)

    def test_truncation_rejected(self):
        for va, value in self.windows.items():
            changed = dict(self.windows)
            changed[va] = value[:-1]
            with self.assertRaises(ValueError):
                CHECK.check_windows(changed)

    def test_coordinate_change_rejected(self):
        changed = dict(self.windows)
        va = min(changed)
        changed[va + 1] = changed.pop(va)
        with self.assertRaisesRegex(ValueError, "coordinate"):
            CHECK.check_windows(changed)

    def test_wrong_target_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            CHECK.authenticate(b"not the captured node")

    def test_wrong_frame_rejected(self):
        with self.assertRaisesRegex(ValueError, "FDE"):
            CHECK.check_frame(self.report["frame"].replace("15d8447", "15d8446"))

    def test_mapping_not_guessed(self):
        for va, value in self.windows.items():
            with self.assertRaisesRegex(ValueError, "mapping"):
                CHECK.mapped_window(value, [], va, len(value))
            with self.assertRaisesRegex(ValueError, "mapping"):
                CHECK.mapped_window(value, [(va, 0, len(value))] * 2, va, len(value))


if __name__ == "__main__":
    unittest.main()
