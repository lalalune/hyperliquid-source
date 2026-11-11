import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_state_compose115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-016-state-compose-434b9f0-115"


class StateCompose115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.Image(tool.BINARY.read_bytes())
        cls.cases = tool.all_cases()[:450]

    def test_regenerated_evidence_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(pathlib.Path(tmp))
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["cases"], 6000)
            self.assertEqual(summary["body_instructions_executed"], [143, 143])
            self.assertEqual(summary["negative_controls"], {"detected": 24, "total": 24})
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
        _, bad, _ = tool.evaluate(self.image, cases=self.cases)
        self.assertEqual(bad, 0)

    def test_layout_is_a_bijection_onto_input_bytes(self):
        seen_in, seen_out = [], []
        for dst, src, off, n, _, _ in tool.LAYOUT:
            seen_out.extend(range(dst, dst + n))
            if src == "in":
                seen_in.extend(range(off, off + n))
        self.assertEqual(sorted(seen_in), list(range(0xbb4)))
        self.assertEqual(sorted(seen_out), list(range(tool.OUT_SIZE - 4)))

    def test_wrong_models_are_detected(self):
        for name in ("swap_b38_b58", "f32_as_f64", "dealloc_always", "dealloc_never", "block_flag_one"):
            _, bad, _ = tool.evaluate(self.image, mut=frozenset([name]), stop_on_first=True, cases=self.cases)
            self.assertGreater(bad, 0, name)

    def test_corrupted_code_bytes_are_detected(self):
        for va, byte, _ in tool.BYTE_MUTANTS[:6]:
            _, bad, _ = tool.evaluate(self.image, override={va: byte}, stop_on_first=True, cases=self.cases)
            self.assertGreater(bad, 0, hex(va))

    def test_static_pins(self):
        consts, _, pad = tool.static_evidence(self.image)
        self.assertEqual(consts["callers"], {"e8_rel32_sites": ["0x3c2ec16"], "relative_addends": []})
        self.assertEqual(consts["got_slots"]["0x64e9528"]["target"], "0x38c2690")
        self.assertEqual(consts["got_slots"]["0x64df508"]["target"], "import memcpy")
        self.assertEqual(pad, 0x434bcf4)

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
                if va <= 0x434bbb6 < va + size:
                    raw[0x434bbb6 - va] = 0x10
                return bytes(raw)
        patched = Patched(self.image.data, check=False)
        with self.assertRaises(tool.ToolError):
            tool.static_evidence(patched)


if __name__ == "__main__":
    unittest.main()
