import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_storage_warm115 as t  # noqa: E402


class StorageWarm115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        t.EMPTY_CTRL = cls.image.word(t.TEMPLATE)
        t.SEED_AT = cls.image.word(t.SEED_GOT)
        cls.cases = t.all_cases()

    def detected(self, mut=frozenset(), override=None):
        # scan the full case list until the first mismatch, so rare paths are not sampled away
        _, bad, _ = t.evaluate(self.image, override=override, mut=mut, stop_on_first=True, cases=self.cases)
        return bad > 0

    def test_wrong_digest_rejected(self):
        data = bytearray(t.BINARY.read_bytes())
        data[self.image.text["offset"] + 1] ^= 0x40
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_code_outside_text_rejected(self):
        end = self.image.text["address"] + self.image.text["size"]
        with self.assertRaises(t.ToolError):
            self.image.code(end + 0x10, 4)
        with self.assertRaises(t.ToolError):
            self.image.code(end - 2, 4)

    def test_static_constants(self):
        consts, decoded = t.static_evidence(self.image)
        self.assertEqual(consts["slots"]["sload"]["target"], "0x4e33680")
        self.assertEqual(consts["slots"]["byte_hasher"]["target"], "0x1770830")
        self.assertEqual(consts["slots"]["storage_reserve"]["target"], "0x3ee1680")
        self.assertEqual(consts["slots"]["journal_grow"]["target"], "0x43bc980")
        self.assertEqual(consts["functions"]["0x4e33680"]["fde_end"], "0x4e33eec")
        self.assertEqual(consts["functions"]["0x2977910"]["fde_end"], "0x2977cc4")
        differing = [r for r in consts["twin_rip_operands"] if not r["same_target"]]
        self.assertEqual([(r["slot_target_a"], r["slot_target_b"]) for r in differing], [("0x4e33680", "0x433bcf0")])
        self.assertEqual(sorted(decoded), sorted(t.FUNCS))

    def test_sample_matches(self):
        _, bad, _ = t.evaluate(self.image, cases=self.cases[::17])
        self.assertEqual(bad, 0)

    def test_rejects_changed_check_byte(self):
        data = bytearray(self.image.data)
        img = t.Image(bytes(data), check=False)
        sec = img.text
        data[0x4e33e27 - sec["address"] + sec["offset"]] = 0x0a
        with self.assertRaises(t.ToolError):
            t.static_evidence(t.Image(bytes(data), check=False))

    def test_model_mutants_detected(self):
        for name in t.MODEL_MUTANTS:
            with self.subTest(name=name):
                self.assertTrue(self.detected(mut=frozenset([name])))

    def test_code_mutants_detected(self):
        for va, byte, _ in t.BYTE_MUTANTS:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertTrue(self.detected(override={va: byte}))


if __name__ == "__main__":
    unittest.main()
