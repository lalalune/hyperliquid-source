import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_storage_cache_load115 as t  # noqa: E402


class StorageCacheLoad115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        t.prepare(cls.image)
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
        self.assertEqual(consts["slots"]["fallible_load"]["target"], "0x433bcf0")
        self.assertEqual(consts["slots"]["byte_hasher"]["target"], "0x1770830")
        self.assertEqual(consts["slots"]["storage_reserve"]["target"], "0x3ee1680")
        self.assertEqual(consts["slots"]["journal_grow"]["target"], "0x43bc980")
        self.assertEqual(consts["slots"]["free"]["target"], "0x635de30")
        self.assertEqual(consts["functions"]["0x433bcf0"]["fde_end"], "0x433c5c9")
        self.assertEqual(consts["functions"]["0x3ed6d80"]["fde_end"], "0x3ed6edc")
        self.assertEqual(consts["functions"]["0x433bcf0"]["instructions"], 524)
        self.assertEqual(sorted(decoded), sorted(t.FUNCS))

    def test_sample_matches(self):
        _, bad, _ = t.evaluate(self.image, cases=self.cases[::11])
        self.assertEqual(bad, 0)

    def test_outcome_families_present(self):
        rows, bad, _ = t.evaluate(self.image, cases=self.cases[:700])
        self.assertEqual(bad, 0)
        seen = {t.outcome(c, got).split("/")[0] + "/" + t.outcome(c, got).split("/")[1] for _, c, _, got, _ in rows}
        for want in ("warm/hit", "cold/hit", "skipped/miss", "cold/created", "cold/storage-some", "warm/acct-err"):
            self.assertIn(want, seen)

    def test_rejects_changed_check_byte(self):
        data = bytearray(self.image.data)
        sec = self.image.text
        data[0x433c4e2 - sec["address"] + sec["offset"]] = 0x0a
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
