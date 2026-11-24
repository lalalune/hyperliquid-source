import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import bridge_caller_source_fields_115 as T  # noqa: E402


class BridgeCallerSourceFields115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = T.collect(ROOT / "artifacts/node/115/hl-node")

    def test_two_complete_caller_extents(self):
        self.assertEqual([(row[0], row[1], row[2], row[3]) for row in self.result["functions"]], [
            (0x44D69F0, 0x44D7210, 2080, 368),
            (0x44D7210, 0x44D7860, 1616, 312),
        ])
        self.assertEqual(len(self.result["instructions"]), 680)

    def test_tag5_source_projection(self):
        rows = [(row[1], row[2], row[3]) for row in self.result["source_spans"] if row[0] == "tag5"]
        self.assertEqual(rows, [
            ("r8+0x58", "tag5_record+0x1", 16),
            ("r8+0x68", "tag5_record+0x11", 4),
            ("r8+0x6c", "tag5_record+0x15", 16),
            ("r8+0x7c", "tag5_record+0x25", 4),
            ("r8+0x0", "tag5_record+0x30", 8),
            ("r8+0x8", "tag5_record+0x38", 8),
        ])

    def test_tag4_passes_fixed_r8_prefix_to_record_helper(self):
        rows = [(row[1], row[2], row[3]) for row in self.result["source_spans"] if row[0] == "tag4"]
        self.assertEqual(rows, [
            ("r8+0x0", "helper_input+0x0", 16),
            ("r8+0x10", "helper_input+0x10", 16),
            ("r8+0x20", "helper_input+0x20", 16),
            ("r8+0x30", "helper_input+0x30", 16),
            ("r8+0x40", "helper_input+0x40", 16),
            ("r8+0x50", "helper_input+0x50", 16),
            ("r8+0x60", "helper_input+0x60", 8),
        ])

    def test_shared_relocated_outer_helper(self):
        self.assertEqual(self.result["outer_helper"], {
            "slot": "0x64eaae8", "relocation_type": 8,
            "symbol_index": 0, "target": "0x4526e40",
        })
        self.assertEqual(self.result["tagged_constructor"], {
            "slot": "0x64eab68", "relocation_type": 8,
            "symbol_index": 0, "target": "0x4526230",
        })

    def test_digest_guard_rejects_wrong_target(self):
        with patch.object(T, "TARGET_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                T.collect(ROOT / "artifacts/node/115/hl-node")

    def test_packet_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            T.write_packet(self.result, Path(a))
            T.write_packet(self.result, Path(b))
            names = sorted(path.name for path in Path(a).iterdir())
            self.assertEqual(names, sorted(path.name for path in Path(b).iterdir()))
            self.assertEqual({name: (Path(a) / name).read_bytes() for name in names},
                             {name: (Path(b) / name).read_bytes() for name in names})
            manifest = (Path(a) / "MANIFEST.sha256").read_text()
            self.assertIn("evidence.json", manifest)
            self.assertEqual(json.loads((Path(a) / "evidence.json").read_text())["analysis"]["execution"],
                             "static decode only; captured executable was not run")


if __name__ == "__main__":
    unittest.main()
