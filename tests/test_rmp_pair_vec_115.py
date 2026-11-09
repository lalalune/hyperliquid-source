import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import rmp_pair_vec_115 as t  # noqa: E402


class PairVecTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        cls.ext = t.extents(cls.image)
        cls.facts = t.facts_of(cls.image, cls.ext)
        cls.cases = list(t.all_cases(cls.facts, {"vec": 120, "pair-b": 80, "pair-a": 80}))

    def run_all(self, cases, mut=frozenset(), override=None):
        return t.evaluate(self.image, self.ext, cases, mut, override)

    def test_digest_is_checked(self):
        bad = self.image.data[:-1] + bytes([self.image.data[-1] ^ 1])
        with self.assertRaises(t.ToolError):
            t.Image(bad)

    def test_all_roles_match_model(self):
        _, bad = self.run_all(self.cases)
        self.assertEqual(bad, [])

    def test_case_mix_has_every_kind(self):
        kinds = set()
        for c in self.cases:
            w = t.model(c)
            kinds.add((c["role"], "alloc" if w["boundary"] else ("ok" if w["result"] is None else "err")))
        for role in ("vec", "pair-b", "pair-a"):
            self.assertIn((role, "ok"), kinds)
            self.assertIn((role, "err"), kinds)
        self.assertIn(("vec", "alloc"), kinds)

    def test_str_header_forms(self):
        self.assertEqual(t.mp_str_head(0), b"\xa0")
        self.assertEqual(t.mp_str_head(31), b"\xbf")
        self.assertEqual(t.mp_str_head(32), b"\xd9\x20")
        self.assertEqual(t.mp_str_head(256), b"\xda\x01\x00")
        self.assertEqual(t.mp_str_head(0x10000), b"\xdb\x00\x01\x00\x00")

    def test_array_header_forms(self):
        self.assertEqual(t.mp_array(15), b"\x9f")
        self.assertEqual(t.mp_array(16), b"\xdc\x00\x10")
        self.assertEqual(t.mp_array(0x10000), b"\xdd\x00\x01\x00\x00")

    def test_pair_ext_name_is_rejected(self):
        c = next(c for c in self.cases if c["role"] == "pair-b" and c["name"] == t.EXT_NAME and c["fault"] is None)
        want = t.model(c)
        self.assertEqual(want["result"][0], t.EXT_TAG)
        self.assertEqual(want["out"], c["prefix"])

    def test_vec_buffered_path_uses_compound(self):
        c = next(c for c in self.cases if c["role"] == "vec" and t.buffered(c["n"]) and not c["oom"]
                 and c["fault"] is None and c["name"] != t.EXT_NAME)
        kinds = [e[0] for e in t.model(c)["events"]]
        self.assertIn("pair-a", kinds)
        self.assertEqual(kinds[0], "malloc")
        self.assertEqual(kinds[-1], "free")

    def test_wrap_length_walks_the_wrapped_span(self):
        for m in (1, 2, 5):
            for j in range(15):
                self.assertEqual(t.iterations(t.wrap_len(m, j)), m)
        self.assertIsNone(t.iterations(t.M64))

    def test_growth_rule(self):
        ev = []
        v = t.Vec(8, b"", ev, frozenset())
        v.push(b"x" * 9)
        self.assertEqual(v.cap, 16)
        v.push(b"y" * 8)
        self.assertEqual(ev[0], ("grow", 8, 16))

    def test_model_mutants_are_caught(self):
        sample = self.cases
        for mut in t.MODEL_MUTANTS:
            hit = False
            for c in sample:
                got = t.run_case(self.machine(), c)
                if t.compare(c, t.model(c, frozenset({mut})), got):
                    hit = True
                    break
            self.assertTrue(hit, mut)

    def machine(self):
        if not hasattr(self, "_m"):
            self._m = t.CaseMachine(self.image)
            self._m.extents = self.ext
        return self._m

    def test_byte_flips_in_bodies_are_caught(self):
        caught = 0
        for va in t.FNS:
            sample = [c for c in self.cases if c["role"] == t.ROLES[va]][:120]
            for _, label, at, bit in t.imm_sites(self.image, self.ext, va, 6):
                _, bad = t.evaluate(self.image, self.ext, sample, override={at: self.image.code(at, 1)[0] ^ bit},
                                    stop_on_first=True)
                caught += bool(bad)
        self.assertGreaterEqual(caught, 8)

    def test_out_of_range_reads_fail(self):
        with self.assertRaises(t.ToolError):
            self.image.read(0x10, 4)
        with self.assertRaises(t.ToolError):
            t.extents_check(self.image, t.VEC_BODY + 1)

    def test_wrong_element_name_address_is_rejected(self):
        with self.assertRaises(t.ToolError):
            t.facts_with_name(self.image, self.ext, t.ELEM_NAME_AT + 1)

    def test_none_field_pushes_nil(self):
        c = next(c for c in self.cases if c["role"] == "pair-a" and c["fault"] is None and c["name"] != t.EXT_NAME
                 and c["fields"][0] is None)
        out = t.model(c)["out"][len(c["prefix"]):]
        self.assertEqual(out[:2], b"\x92\xc0")


if __name__ == "__main__":
    unittest.main()
