import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_rmp_dispatch115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-016-rmp-front-end-115"
CACHE = {}


def shared():
    if not CACHE:
        img = tool.load_image()
        CACHE["img"] = img
        CACHE["table"] = tool.jump_table(img)
        CACHE["rig"] = tool.Rig(img)
        CACHE["cases"] = list(tool.all_cases(CACHE["table"]))
    return CACHE


class RmpFrontEnd115(unittest.TestCase):
    def setUp(self):
        self.c = shared()

    def test_regenerated_evidence_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary, neg, det = tool.generate(pathlib.Path(tmp))
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(neg, det)
            names = sorted(p.name for p in PACKET.iterdir() if p.suffix in (".tsv", ".json"))
            self.assertEqual(names, sorted(p.name for p in pathlib.Path(tmp).iterdir()))
            for name in names:
                self.assertEqual((PACKET / name).read_bytes(), (pathlib.Path(tmp) / name).read_bytes(), name)

    def test_model_agrees_with_machine_on_a_slice(self):
        n, bad, first = tool.evaluate(self.c["rig"], self.c["table"], self.c["cases"][::9])
        self.assertGreater(n, 1000)
        self.assertEqual((bad, first), (0, None))

    def test_jump_table_and_extent(self):
        t = self.c["table"]
        self.assertEqual(len(t), 256)
        self.assertEqual(t[0xC4], 0x3266FD7)
        self.assertEqual(t[0xD9], 0x3267054)
        self.assertEqual(sum(1 for x in t if x == tool.UD2_VA), 188)
        self.assertEqual(tool.base.fde_rows(self.c["img"], [tool.START]), {tool.START: (tool.START, tool.END)})

    def test_fresh_marker_classes(self):
        t = self.c["table"]
        self.assertEqual(tool.model(1, 0, b"", t)[0], "ret")
        self.assertEqual(tool.model(1, 0, b"\x05", t)[:7], ("call", 0x341FF00, tool.OUT, tool.RD, 0, 5, 0))
        self.assertEqual(tool.model(1, 0, b"\xa2hi", t)[1], 0x16815E0)
        self.assertEqual(tool.model(1, 0, b"\xa3hi", t)[0], "ret")
        self.assertEqual(tool.model(1, 0, b"\xc1", t)[1][:2], b"\x02\xc1")

    def test_wrong_models_are_caught(self):
        sub = self.c["cases"][::11]
        for name in tool.MODEL_MUTANTS:
            self.assertTrue(tool.model_mutant_detected(self.c["rig"], self.c["table"], name, sub), name)

    def test_corrupt_inputs_are_rejected(self):
        self.assertTrue(tool.image_rejected("flipped-byte"))
        self.assertTrue(tool.unmapped_rejected(self.c["img"]))
        for tag in (0xE1, 0xF0, 0xFF):
            self.assertTrue(tool.domain_rejected(self.c["table"], tag))
        self.assertTrue(tool.table_mutant_detected(self.c["rig"], self.c["table"], 0xC4, 0xC5, self.c["cases"][::5]))

    def test_byte_mutant_is_caught(self):
        sites = tool.jcc_sites(tool.decoded_function(self.c["img"]))
        found = [tool.byte_mutant_detected(self.c["img"], self.c["table"], v, self.c["cases"][::13]) for v, _ in sites[:6]]
        self.assertTrue(any(found))

    def test_measure_file(self):
        m = json.loads((PACKET / "measure.json").read_text())
        self.assertEqual(sorted(m), ["cases", "negative_controls", "negative_detected"])
        self.assertEqual(m["negative_controls"], m["negative_detected"])
        self.assertEqual(struct.calcsize("<QQ"), 16)


if __name__ == "__main__":
    unittest.main()
