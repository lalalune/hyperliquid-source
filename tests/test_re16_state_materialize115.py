import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_state_materialize115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-016-state-materialize-3c2e860-115"


class StateMaterialize115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.Image(tool.BINARY.read_bytes())
        cls.consts, _, cls.pad, cls.drops = tool.static_evidence(cls.image)
        cls.cases = tool.all_cases()[:450]

    def test_regenerated_evidence_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(pathlib.Path(tmp))
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["cases"], 6000)
            self.assertEqual(summary["body_instructions_executed"], [422, 422])
            self.assertEqual(summary["negative_controls"], {"detected": 20, "total": 20})
            names = sorted(p.name for p in PACKET.iterdir() if p.suffix in (".tsv", ".json"))
            self.assertEqual(names, sorted(p.name for p in pathlib.Path(tmp).iterdir()))
            for name in names:
                self.assertEqual((pathlib.Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_manifest(self):
        rows = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        listed = {}
        for row in rows:
            digest, name = row.split("  ", 1)
            listed[name] = digest
        self.assertEqual(sorted(listed), sorted(p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256"))
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_model_matches_machine_code(self):
        _, bad, _ = tool.evaluate(self.image, self.drops, cases=self.cases)
        self.assertEqual(bad, 0)

    def test_layout_covers_output_once_and_input_outside_sub_value(self):
        seen_in, seen_out = [], []
        for dst, src, off, n, _ in tool.LAYOUT:
            seen_out.extend(range(dst, dst + n))
            if src == "in":
                seen_in.extend(range(off, off + n))
        self.assertEqual(sorted(seen_out), list(range(0x42c5)))
        self.assertEqual(sorted(seen_in), list(range(tool.SUB_AT)) + list(range(tool.SUB_AT + tool.SUB_SIZE, 0x27a5)))
        self.assertEqual(tool.OUT_SIZE - tool.IN_SIZE, tool.BLOCK)
        self.assertEqual(tool.COMPOSED, tool.SUB_SIZE + tool.BLOCK)

    def test_wrong_models_are_detected(self):
        for name in tool.MODEL_MUTANTS:
            _, bad, _ = tool.evaluate(self.image, self.drops, mut=frozenset([name]), stop_on_first=True,
                                      cases=self.cases)
            self.assertGreater(bad, 0, name)

    def test_corrupted_code_bytes_are_detected(self):
        for va, byte, _ in tool.BYTE_MUTANTS[:5]:
            _, bad, _ = tool.evaluate(self.image, self.drops, override={va: byte}, stop_on_first=True,
                                      cases=self.cases)
            self.assertGreater(bad, 0, hex(va))

    def test_static_pins(self):
        self.assertEqual(self.consts["callers"]["e8_rel32_sites"], [])
        self.assertEqual(self.consts["callers"]["relative_addends"], ["0x64e9630"])
        self.assertEqual(self.consts["callers"]["slot_call_sites_in_boundary"], ["0x3c13665"])
        self.assertEqual(self.consts["callers"]["composer_e8_rel32_sites"], ["0x3c2ec16"])
        self.assertEqual(self.pad, 0x3c2f2d5)
        normal = [r["role"] for r in self.consts["calls"] if not r["in_landing_pad"]]
        self.assertEqual(normal.count("composer"), 1)
        self.assertEqual(len(normal), 17)

    def test_wrong_binary_digest_rejected(self):
        data = bytearray(self.image.data)
        data[self.image.text["offset"] + 0x10] ^= 0x40
        with self.assertRaises(tool.ToolError):
            tool.Image(bytes(data))

    def test_address_outside_text_rejected(self):
        with self.assertRaises(tool.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"], 4)

    def test_changed_expected_byte_rejected(self):
        class Patched(tool.Image):
            def code(inner, va, size):
                raw = bytearray(super().code(va, size))
                if va <= 0x3c2f1bc < va + size:
                    raw[0x3c2f1bc - va] = 0xd0
                return bytes(raw)
        patched = Patched(self.image.data, check=False)
        with self.assertRaises(tool.ToolError):
            tool.static_evidence(patched)


if __name__ == "__main__":
    unittest.main()
