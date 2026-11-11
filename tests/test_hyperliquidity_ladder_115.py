import copy
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import hyperliquidity_ladder_115 as T  # noqa: E402

cpu = T.cpu
DATA = T.TARGET.read_bytes()
IMAGE = cpu.Image(DATA)
CONSTS = T.constants(IMAGE)
BASE = dict(kind="tick", rows=[(0, 1), (1, 0)], toks=[(0, 8), (2, 10)], entries=[], k0=1, k1=2, tok=0, price=1, calls=[])


def tick(**kw):
    got, trace, _ = T.execute(IMAGE, dict(BASE, **kw))
    return got, trace


class TickTests(unittest.TestCase):
    def test_digest(self):
        self.assertTrue(T.check_digest(DATA))
        damaged = bytearray(DATA)
        damaged[7] ^= 1
        self.assertFalse(T.check_digest(bytes(damaged)))

    def test_five_significant_digits(self):
        toks = [(0, 30), (0, 30)]
        for price, want in ((1, 1), (99999, 1), (100000, 10), (999999, 10), (1000000, 100), (10 ** 10, 10 ** 6),
                            (10 ** 15, 10 ** 11), (10 ** 19 - 1, 10 ** 14), (10 ** 19, 10 ** 15), (T.U64, 10 ** 15)):
            self.assertEqual(tick(price=price, toks=toks)[0], ("ok", want), price)

    def test_decimals_clamp(self):
        # tick = min(digit tick, 10 ** (second[0x49] - first[0x48]))
        self.assertEqual(tick(price=10 ** 12, toks=[(2, 0), (0, 4)])[0], ("ok", 100))
        self.assertEqual(tick(price=10 ** 12, toks=[(2, 0), (0, 2)])[0], ("ok", 1))
        self.assertEqual(tick(price=10 ** 12, toks=[(0, 0), (0, 40)])[0], ("ok", 10 ** 8))
        self.assertEqual(tick(price=10 ** 12, toks=[(0, 0), (0, 200)])[0], ("ok", 10 ** 8))

    def test_underflow_panic(self):
        got, _ = tick(toks=[(5, 0), (0, 3)])
        self.assertEqual(got, ("panic", "decimals_underflow"))

    def test_bounds_panics(self):
        self.assertEqual(tick(tok=2)[0], ("panic", "rows_oob"))
        self.assertEqual(tick(rows=[(0, 9)])[0], ("panic", "tokens_oob"))

    def test_special_set(self):
        self.assertEqual(tick(entries=[0])[0], ("ok", 1000))
        self.assertEqual(tick(entries=[7])[0][0], "ok")
        got, trace = tick(entries=[7, 8], calls=[(5, 1, 0)])
        self.assertEqual(got, ("ok", 1000))
        self.assertEqual(trace[0][0], "hash")
        self.assertEqual(tick(entries=[7, 8], calls=[(5, 1, 2)])[0], ("panic", "map_oob"))
        self.assertEqual(tick(entries=[7, 8], calls=[(5, 2, 0)])[0][0], "ok")


class LadderTests(unittest.TestCase):
    def ladder(self, **kw):
        case = dict(BASE, kind="ladder", price=100000, n=6, size=3, toks=[(0, 30), (0, 30)])
        case.update(kw)
        return T.execute(IMAGE, case)[0]

    def test_fixed_ladder(self):
        got = self.ladder()
        self.assertEqual(got[0], "ok")
        self.assertEqual(got[1], (100000, 100300, 100600, 100900, 101200, 101500))
        self.assertEqual((got[2], got[3]), (3, 8))
        self.assertTrue(got[4] and got[5])

    def test_tick_floor_of_start(self):
        self.assertEqual(self.ladder(price=123456, n=1)[1], (123450,))
        self.assertEqual(self.ladder(price=0, n=2)[1][0], 1)

    def test_saturation(self):
        got = self.ladder(price=T.U64, n=3)
        self.assertEqual(got[1][0], T.U64 // 10 ** 15 * 10 ** 15)

    def test_spec_matches(self):
        for i in range(400):
            ok, _, _ = T.compare(IMAGE, T.make_case(i), CONSTS)
            self.assertTrue(ok, i)


class CostTests(unittest.TestCase):
    def cost(self, levels, take, size):
        case = dict(kind="cost", levels=[(0, 0, p) for p in levels], take=take, size=size, cap=len(levels), calls=[])
        return T.execute(IMAGE, case)[0]

    def test_sum(self):
        self.assertEqual(self.cost([5, 6, 7], 2, 10), ("ok", 1, 110))
        self.assertEqual(self.cost([5, 6, 7], 0, 10), ("ok", 1, 0))
        self.assertEqual(self.cost([5, 6, 7], 99, 10), ("ok", 1, 180))

    def test_overflow_returns_previous_sum(self):
        big = T.COST_LIMIT
        self.assertEqual(self.cost([4, big], 2, 1), ("ok", 1, 4 + big) if 4 + big <= T.U64 else None)
        self.assertEqual(self.cost([4, big + 1], 2, 1), ("ok", 0, 4))
        self.assertEqual(self.cost([T.COST_LIMIT, T.COST_LIMIT, T.COST_LIMIT], 3, 1)[1], 0)


class ControlTests(unittest.TestCase):
    def test_spec_mutants_detected(self):
        for name, _ in T.SPEC_MUTANTS[:6]:
            self.assertIsNotNone(T.run_cases(IMAGE, CONSTS, 300, (name,)), name)

    def test_clean_run_has_no_mismatch(self):
        self.assertIsNone(T.run_cases(IMAGE, CONSTS, 300))

    def test_byte_patch_detected(self):
        patch = T.BYTE_PATCHES[0]
        clone = T.patched_image(IMAGE, patch)
        self.assertIsNotNone(T.run_cases(clone, CONSTS, 300))

    def test_patch_pattern_outside_body_refused(self):
        bad = ("x", T.COST, b"\xde\xad\xbe\xef\x01", 0, 1, "none", )
        with self.assertRaises(cpu.ToolError):
            T.patched_image(IMAGE, ("x", T.COST, b"\xde\xad\xbe\xef\x01", 0, 1, "none"))
        self.assertEqual(len(bad), 6)

    def test_misc_controls_all_hold(self):
        for name, _, ok in T.misc_controls(IMAGE):
            self.assertTrue(ok, name)

    def test_location_table(self):
        for va, name in T.LOCATIONS.items():
            self.assertTrue(T.decode_location(IMAGE, va)[0].endswith(".rs"), name)

    def test_unlisted_location_refused(self):
        with self.assertRaises(cpu.ToolError):
            T.panic_name(IMAGE, 0x400100)

    def test_extents(self):
        for fn, size in T.SIZES.items():
            self.assertEqual(T.body_extent(IMAGE, fn), size)
        with self.assertRaises(cpu.ToolError):
            T.body_extent(IMAGE, T.TICK + 1)


class OutputTests(unittest.TestCase):
    def test_no_server_paths_in_packet_files(self):
        banned = ("/ho" + "me/", "/m" + "nt/", "/s" + "rv/", "/ro" + "ot/", "/t" + "mp/", "/o" + "pt/", "/v" + "ar/", "/e" + "tc/")
        for path in (ROOT / "tools/hyperliquidity_ladder_115.py", Path(__file__)):
            text = path.read_text()
            for b in banned:
                self.assertNotIn(b, text, (path.name, b))


if __name__ == "__main__":
    unittest.main()
