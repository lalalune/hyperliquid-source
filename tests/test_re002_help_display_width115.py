import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-002-node115-help-display-width"


@unittest.skipUnless(importlib.util.find_spec("capstone"), "requires Capstone")
class DisplayWidthCalls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / "artifacts/node/115/hl-node"
        if not path.exists() or path.stat().st_size != 105896032:
            raise unittest.SkipTest("requires the materialized node 115 artifact")
        spec = importlib.util.spec_from_file_location("node115_display_width_capture", PACKET / "capture.py")
        cls.subject = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.subject)
        cls.data = path.read_bytes()
        cls.fdes = {r["start"]: r["end"] for r in cls.subject.eh_frame_records(cls.data)[1]}

    def test_mode_selected_at_every_recorded_call(self):
        self.assertEqual(self.subject.digest(self.data), self.subject.TARGET_SHA)
        saved = json.loads((PACKET / "results.json").read_text())
        sites, _ = self.subject.call_sites(self.data, self.fdes)
        self.assertEqual(sites, saved["binding"]["narrow_calls"])

    def test_register_change_is_detected_at_the_selected_call(self):
        site = 0x1641ADA
        offset, original = self.subject.elf.read(self.data, site - 2, 2)
        self.assertEqual(original, bytes.fromhex("31d2"))
        changed = bytearray(self.data)
        changed[offset:offset + 2] = bytes.fromhex("31c2")
        with self.assertRaisesRegex(ValueError, "changed call-site"):
            self.subject.call_sites(changed, self.fdes)
