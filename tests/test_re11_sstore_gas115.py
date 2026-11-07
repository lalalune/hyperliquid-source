import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_sstore_gas115 as t  # noqa: E402


class SstoreGas115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
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
        self.assertEqual(sorted(consts["handler_direct_calls"]["0x2994990"].values()),
                         ["0x2977910", "0x2977910", "0x299f680", "0x299f910"])
        self.assertEqual(sorted(consts["handler_direct_calls"]["0x2994490"].values()),
                         ["0x2977cd0", "0x2977cd0", "0x299f680", "0x299f910"])
        self.assertEqual(len(consts["twin_operands"]), 6)
        self.assertEqual(consts["functions"]["0x2994990"]["instructions"], 288)
        self.assertEqual(consts["functions"]["0x2994490"]["instructions"], 288)
        self.assertEqual(consts["functions"]["0x299f910"]["instructions"], 105)
        self.assertEqual(consts["functions"]["0x299f680"]["instructions"], 187)
        self.assertEqual(sorted(decoded), sorted(t.FUNCS))

    def test_reconstruction_examples(self):
        p = {off: 0 for off in t.PARAM_OFFS}
        p.update({0xa0: 20000, 0xa8: 2900, 0xb0: 4800, 0xd0: 2100, 0x138: 19900, 0x140: 2800})
        self.assertEqual(t.sstore_cost(p, 1, 0, 0, 5, 1), 2100 + 20000)
        self.assertEqual(t.sstore_cost(p, 1, 7, 7, 5, 0), 2900)
        self.assertEqual(t.sstore_cost(p, 1, 7, 6, 5, 0), 0)
        self.assertEqual(t.sstore_cost(p, 0, 9, 0, 5, 1), 20000)
        self.assertEqual(t.sstore_refund(p, 1, 7, 7, 0), 4800)
        self.assertEqual(t.sstore_refund(p, 1, 7, 0, 7), -4800 + 2800)
        self.assertEqual(t.sstore_refund(p, 1, 0, 3, 0), 19900)
        self.assertEqual(t.sstore_refund(p, 0, 7, 3, 0), 4800)

    def test_sample_matches(self):
        _, bad, _ = t.evaluate(self.image, cases=self.cases[::9])
        self.assertEqual(bad, 0)

    def test_outcome_families_present(self):
        rows, bad, _ = t.evaluate(self.image, cases=self.cases[:800])
        self.assertEqual(bad, 0)
        seen = {t.outcome(c, got).split("/")[0] for _, c, _, got, _ in rows}
        for want in ("ok", "out-of-gas", "sentry", "static", "underflow", "store-error", "panic"):
            self.assertIn(want, seen)

    def test_rejects_changed_check_byte(self):
        data = bytearray(self.image.data)
        sec = self.image.text
        data[0x2994aab - sec["address"] + sec["offset"]] = 0x37
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
