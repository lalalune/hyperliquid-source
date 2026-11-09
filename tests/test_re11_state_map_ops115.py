import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_state_map_ops115 as t  # noqa: E402


class StateMapOps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = t.BINARY.read_bytes()
        cls.image = t.al.Image(cls.data)

    def map_cases(self, spec, count, mut=frozenset(), start=0):
        m = t.Mach(self.image)
        s = t.Stream(f"cases-{spec[0]:x}")
        bad = 0
        for n in range(count):
            c = t.make_map_case(s, spec, n + start)
            got = t.run_map(self.image, spec, c, shared=m)
            bad += not t.compare_map(spec, c, got, mut)
        return bad

    def test_every_map_body_matches_the_model(self):
        for spec in t.FUNCS:
            self.assertEqual(self.map_cases(spec, 36), 0, hex(spec[0]))

    def test_install_matches_the_model(self):
        m = t.Mach(self.image)
        s = t.Stream("cases-install")
        outcomes = set()
        for n in range(96):
            c = t.make_install_case(s, n, self.image)
            got = t.run_install(self.image, c, shared=m)
            self.assertTrue(t.compare_install(self.image, c, got), (n, c["kind"]))
            outcomes.add(t.install_outcome(c, got))
        self.assertTrue({"early_return", "ud2", "installed_miss", "installed_shared"} <= outcomes)

    def test_model_mutants_are_detected(self):
        for spec, mut in ((t.FUNCS[0], "swap_words"), (t.FUNCS[0], "seed_ignored"), (t.FUNCS[7], "k3_plain"),
                          (t.FUNCS[10], "no_items_check"), (t.FUNCS[3], "cmp_short"), (t.FUNCS[9], "growth_inverted")):
            self.assertGreater(self.map_cases(spec, 120, frozenset([mut])), 0, (hex(spec[0]), mut))

    def test_install_mutants_are_detected(self):
        for mut in ("no_empty_shortcut", "swap_words", "h2_56"):
            m = t.Mach(self.image)
            s = t.Stream("cases-install")
            seen = 0
            for n in range(120):
                c = t.make_install_case(s, n, self.image)
                got = t.run_install(self.image, c, shared=m)
                seen += not t.compare_install(self.image, c, got, frozenset([mut]))
            self.assertGreater(seen, 0, mut)

    def test_corrupted_code_is_detected(self):
        spec = t.FUNCS[0]
        lo, hi = t.al.fde_rows(self.image, {spec[0]})[spec[0]]
        m = t.Mach(self.image)
        s = t.Stream("cases-3ed7040")
        for n in range(40):
            t.run_map(self.image, spec, t.make_map_case(s, spec, n), shared=m)
        patches = [p for p in t.corruptions(self.image, lo, hi, m.seen) if p[1] == "jcc_invert"][:6]
        self.assertGreaterEqual(len(patches), 4)
        hits = sum(t.detect_corruption_map(self.image, spec, p, 60) for p in patches)
        self.assertGreaterEqual(hits, 4)

    def test_wrong_geometry_is_detected(self):
        spec, other = t.FUNCS[0], t.FUNCS[9]
        wrong = (spec[0], spec[1], other[2], other[3], other[4], spec[5], spec[6])
        m = t.Mach(self.image)
        s = t.Stream("cases-3ed7040")
        bad = 0
        for n in range(30):
            c = t.make_map_case(s, spec, n)
            bad += not t.compare_map(wrong, c, t.run_map(self.image, spec, c, shared=m))
        self.assertGreater(bad, 0)

    def test_wrong_binary_and_range_are_rejected(self):
        flipped = bytearray(self.data)
        flipped[len(flipped) // 2] ^= 1
        with self.assertRaises(t.ToolError):
            t.al.Image(bytes(flipped))
        with self.assertRaises(t.ToolError):
            self.image.code(0x10, 16)

    def test_hash_matches_hand_computed_value(self):
        key = bytes(range(20))
        g, seed = 0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321
        k0, k1 = int.from_bytes(key[:8], "little"), int.from_bytes(key[8:16], "little")
        k2 = int.from_bytes(key[16:], "little")
        p = (k1 ^ g) * (k0 ^ seed)
        x = ((p & t.M64) ^ (p >> 64)) ^ k2
        q = x * g
        self.assertEqual(t.hash_key(key, seed, g), (q & t.M64) ^ (q >> 64))

    def test_group_wrap_fix_and_mirror(self):
        ctrl = bytearray(b"\xff" * 20)
        t.set_ctrl(ctrl, 3, 1, 0x12)
        self.assertEqual(ctrl[17], 0x12)
        ctrl = bytearray(b"\xff" * 20)
        ctrl[0] = 0x11
        ctrl[17:20] = b"\xff\xff\xff"
        self.assertEqual(t.insert_slot(ctrl, 3, 0) in (1, 2, 3), True)


if __name__ == "__main__":
    unittest.main()
