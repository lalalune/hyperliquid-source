import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_transient_storage115 as t  # noqa: E402


class TransientStorage115(unittest.TestCase):
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
        self.assertEqual(consts["direct_calls"]["0x2994410"], {"0x299445c": "0x295f490"})
        self.assertEqual(consts["direct_calls"]["0x2994e90"], {"0x2994f0c": "0x2972390"})
        self.assertEqual(consts["direct_calls"]["0x295f490"], {})
        self.assertEqual(consts["functions"]["0x2994410"]["instructions"], 36)
        self.assertEqual(consts["functions"]["0x2994e90"]["instructions"], 39)
        self.assertEqual(consts["functions"]["0x295f490"]["instructions"], 132)
        slots = consts["opcode_table_slots"]
        self.assertEqual(slots["0x64414b0+0x40"], {"opcode": "0x5c", "target": "0x2994410"})
        self.assertEqual(slots["0x64421a0+0x48"], {"opcode": "0x5d", "target": "0x2994e90"})
        self.assertEqual(slots["0x64414b0+0x0"]["target"], "0x2993ff0")
        self.assertEqual(consts["hash_seed"]["target"], "0x64ffe90")
        self.assertFalse(consts["hash_seed"]["target_section_has_file_bytes"])
        self.assertEqual(sorted(decoded), sorted(t.FUNCS))

    def test_wrong_opcode_slot_rejected(self):
        saved = dict(self.image.relative)
        try:
            self.image.relative[0x64414b0 + 0x40] = 0x2994e90
            with self.assertRaises(t.ToolError):
                t.opcode_slots(self.image)
        finally:
            self.image.relative = saved

    def test_hash_examples(self):
        # with secret 0 and seed 1 the address hash reduces to one folded multiply
        addr = bytes(range(1, 21))
        a0 = int.from_bytes(addr[0:8], "little")
        a1 = int.from_bytes(addr[8:16], "little") ^ 1
        p = a0 * a1
        self.assertEqual(t.addr_hash(addr, 0, 1), (p & t.M64) ^ int.from_bytes(addr[16:20], "little") ^ (p >> 64))
        # the key hash reads all four limbs: limb 3 changes the second multiplier
        k = 5 | 7 << 64 | 11 << 128
        self.assertNotEqual(t.key_hash(k, 3, 9), t.key_hash(k | 1 << 192, 3, 9))
        self.assertEqual(t.key_hash(k, 3, 9), t.key_hash(k | 1 << 192, 3, 9, frozenset(["hash_no_k3"])))

    def test_layout_needs_an_empty_slot(self):
        with self.assertRaises(t.ToolError):
            t.layout(16, [], [], [(i, 1, b"x") for i in range(16)])

    def test_sample_matches(self):
        _, bad, _ = t.evaluate(self.image, cases=self.cases[::7])
        self.assertEqual(bad, 0)

    def test_outcome_families_present(self):
        rows, bad, _ = t.evaluate(self.image, cases=self.cases[:800])
        self.assertEqual(bad, 0)
        seen = {t.outcome(c, want, got) for _, c, want, got, _ in rows}
        for want in ("tload/not-activated", "tload/underflow", "tload/ok/value/hit", "tload/ok/value/cluster",
                     "tload/ok/zero/empty-inner", "tload/ok/zero/empty-outer", "tload/ok/zero/near-key",
                     "tload/ok/zero/near-addr", "tstore/not-activated", "tstore/static-call", "tstore/underflow",
                     "tstore/ok/write-handed-on"):
            self.assertIn(want, seen)

    def test_rejects_changed_check_byte(self):
        data = bytearray(self.image.data)
        sec = self.image.text
        data[0x2994f1c - sec["address"] + sec["offset"]] = 0x29
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
