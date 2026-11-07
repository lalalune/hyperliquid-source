import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import twap_slice_115 as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-twap-slice-115"

# Hand-checked scenarios: (name, order fields, case fields, perp result, spot result).
# Results are (order, size, price), (reschedule, stub calls) or (panic, kind).
NOW = (tool.pack_date(2025, 100), 3600, 123456789)
GOLDEN = (
    ('plain buy',
     {}, {},
     ('order', 24793, 1030100),
     ('order', 24793, 1030100)),
    ('plain sell',
     {'side': 1}, {},
     ('order', 24793, 970100),
     ('order', 24793, 970100)),
    ('whole remainder small',
     {'total': 20000, 'counter': 7}, {'mid': 97, 'tick': 1, 'top': (97, 97)},
     ('order', 20000, 100),
     ('order', 20000, 100)),
    ('whole remainder boundary',
     {'total': 300000, 'counter': 60}, {'mid': 97, 'tick': 100, 'top': (97, 97)},
     ('order', 300000, 100),
     ('order', 300000, 100)),
    ('one over boundary',
     {'total': 300001, 'counter': 60}, {'mid': 97, 'tick': 100, 'top': (97, 97)},
     ('order', 120000, 100),
     ('order', 300001, 100)),
    ('last step takes target total',
     {'total': 1000000, 'counter': 121}, {},
     ('order', 24793, 1030100),
     ('order', 24793, 1030100)),
    ('counter past last step',
     {'total': 1000000, 'counter': 500}, {},
     ('order', 24793, 1030100),
     ('order', 24793, 1030100)),
    ('executed above target',
     {'total': 1000000, 'counter': 1, 'executed': 900000}, {},
     ('reschedule', ('find user', 'find order', 'drop', 'top', 'tick', 'advance')),
     ('reschedule', ('find user', 'find order', 'mid', 'tick', 'advance'))),
    ('negative duration means one step',
     {'duration': -5.0, 'counter': 1, 'total': 1000000}, {},
     ('order', 1000000, 1030100),
     ('order', 1000000, 1030100)),
    ('float("nan") duration means one step',
     {'duration': float("nan"), 'counter': 1, 'total': 1000000}, {},
     ('order', 1000000, 1030100),
     ('order', 1000000, 1030100)),
    ('infinite duration means one step',
     {'duration': float("inf"), 'counter': 0, 'total': 1000000}, {},
     ('order', 12, 1030100),
     ('order', 1165, 1030100)),
    ('tiny price big floor',
     {'total': 1000000, 'counter': 3, 'side': 0}, {'mid': 3, 'tick': 1, 'top': (3, 3)},
     ('order', 1000000, 3),
     ('order', 1000000, 3)),
    ('price above unit gives floor one',
     {'total': 1000000000, 'counter': 2}, {'mid': 20000000, 'tick': 1, 'top': (20000000, 20000000)},
     ('order', 16528000, 20600000),
     ('order', 16528000, 20600000)),
    ('jitter on',
     {'randomize': 1, 'counter': 5}, {},
     ('order', 24793, 1030100),
     ('order', 24793, 1030100)),
    ('jitter off',
     {'randomize': 0, 'counter': 5}, {},
     ('order', 24793, 1030100),
     ('order', 24793, 1030100)),
    ('zero top price',
     {}, {'top': (0, 5)},
     ('reschedule', ('find user', 'find order', 'drop', 'top', 'advance')),
     ('order', 24793, 1030100)),
    ('executed equals total',
     {'total': 1000, 'executed': 1000, 'counter': 7}, {},
     ('reschedule', ('find user', 'find order', 'drop', 'top', 'tick', 'advance')),
     ('reschedule', ('find user', 'find order', 'mid', 'tick', 'advance'))),
    ('executed above total',
     {'total': 1000, 'executed': 2000, 'counter': 7}, {},
     ('reschedule', ('find user', 'find order', 'drop', 'top', 'tick', 'advance')),
     ('reschedule', ('find user', 'find order', 'mid', 'tick', 'advance'))),
    ('big size rounds to five figures',
     {'total': 1000000000000, 'counter': 60, 'duration': 1800.0}, {},
     ('order', 49180000000, 1030100),
     ('order', 49180000000, 1030100)),
    ('flag set',
     {}, {'flag': 1},
     ('reschedule', ('find user', 'find order', 'advance')),
     ('reschedule', ('find user', 'find order', 'advance'))),
    ('flag set with once state',
     {}, {'flag': 1, 'once': 1},
     ('reschedule', ('find user', 'find order', 'once', 'advance')),
     ('reschedule', ('find user', 'find order', 'once', 'advance'))),
    ('market beyond table',
     {'asset': 40001}, {},
     ('panic', 'unwrap'),
     ('order', 24793, 1030100)),
    ('book beyond table',
     {'asset': 29999}, {},
     ('panic', 'index'),
     ('order', 24793, 1030100)),
)



class TwapSlice115(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    setUpClass = classmethod(prepare)

    def run_cases(self, count, spec=None, copies=range(4)):
        wrong = 0
        for copy in copies:
            for case in tool.cases_for(copy, count):
                ok, _, _ = tool.check(self.harness, copy, case, spec)
                wrong += not ok
        return wrong

    def test_bytes_match_specification(self):
        self.assertEqual(self.run_cases(300), 0)

    def test_every_outcome_is_reached(self):
        seen = set()
        for copy in range(4):
            for case in tool.cases_for(copy, 300):
                _, _, actual = tool.check(self.harness, copy, case)
                seen.add((tool.COPIES[copy]["family"], tool.outcome_of(actual)))
        for family in (tool.PERP, tool.SPOT):
            for outcome in ("order", "reschedule", "none"):
                self.assertIn((family, outcome), seen)
        self.assertIn((tool.PERP, "panic"), seen)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_address_outside_every_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x10)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.COPIES[0]["slice"] + 1)

    def test_wrong_specifications_are_caught(self):
        for variant in tool.VARIANTS:
            wrong = self.run_cases(400, lambda c, k, v=variant: tool.spec_slice(c, k, v))
            self.assertGreater(wrong, 0, variant)

    def test_flipped_conditions_are_caught(self):
        for copy, sites in ((0, (0x5A30E6D, 0x5A30EAF)), (2, ())):
            start, end = self.image.exact_fde(tool.COPIES[copy]["slice"])
            rows = {row.va: row for row in tool.decode_range(self.image, start, end)}
            probe = list(tool.cases_for(copy, 400))
            for site in sites:
                at, byte = tool.jcc_patch(self.image, rows[site])
                self.assertTrue(tool.detects(self.image, copy, {at: byte}, probe), hex(site))

    def test_copy_offsets_are_not_interchangeable(self):
        # The second perp copy reads the market table at +0x1338; the first at +0x7c8.
        swapped = dict(tool.COPIES[1])
        saved = tool.COPIES
        try:
            tool.COPIES = (saved[0], dict(swapped, markets=0x7C8, count=0x7D0), saved[2], saved[3])
            harness = tool.Harness(self.image)
            wrong = sum(not tool.check(harness, 1, case)[0] for case in tool.cases_for(1, 200))
        finally:
            tool.COPIES = saved
        self.assertGreater(wrong, 0)

    def test_render_is_deterministic_and_counted(self):
        first = tool.render(self.image, 120, 20, 2)
        second = tool.render(self.image, 120, 20, 2)
        self.assertEqual(first, second)
        expected = 4 * (120 + len(list(tool.edge_cases(0))))
        self.assertIn('"cases": %d' % expected, first["measure.json"])

    def test_committed_manifest(self):
        manifest = FOLDER / "MANIFEST.sha256"
        self.assertTrue(manifest.exists())
        for line in manifest.read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


class GoldenScenarios(unittest.TestCase):
    """Literal results, so that a drift in the specification itself cannot hide behind the comparison."""

    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    setUpClass = classmethod(prepare)

    def result(self, copy, name, order_fields, case_fields):
        fields = dict(asset=20003, total=1000000, duration=3600.0, side=0, counter=7)
        fields.update(order_fields)
        case = tool.SliceCase(name, order=tool.Order(**fields), now=NOW, **case_fields)
        ok, _, actual = tool.check(self.harness, copy, case)
        self.assertTrue(ok, name)
        kind = tool.outcome_of(actual)
        if kind == "order":
            return ("order", tool.struct.unpack_from("<Q", actual["bytes"], 8)[0], tool.struct.unpack_from("<Q", actual["bytes"], 0x20)[0])
        if kind == "panic":
            return ("panic", actual["stop"][0])
        return (kind, tuple(event[0] for event in actual["events"]))

    def test_perp_copies(self):
        for name, order_fields, case_fields, perp, _ in GOLDEN:
            for copy in (0, 1):
                self.assertEqual(self.result(copy, name, order_fields, case_fields), perp, (name, copy))

    def test_spot_copies(self):
        for name, order_fields, case_fields, _, spot in GOLDEN:
            for copy in (2, 3):
                self.assertEqual(self.result(copy, name, order_fields, case_fields), spot, (name, copy))

    def test_side_changes_only_price(self):
        buy = self.result(0, "buy", {}, {})
        sell = self.result(0, "sell", dict(side=1), {})
        self.assertEqual(buy[1], sell[1])
        self.assertEqual((buy[2], sell[2]), (1030100, 970100))

    def test_flag_never_reaches_the_market_tables(self):
        # A set flag hands off before the market bound, so an unknown market does not panic.
        for copy in range(4):
            case = tool.SliceCase("flag", order=tool.Order(asset=99999999), now=NOW, flag=1)
            ok, _, actual = tool.check(tool.Harness(self.image), copy, case)
            self.assertTrue(ok)
            self.assertEqual(tool.outcome_of(actual), "reschedule")


class EngineUnits(unittest.TestCase):
    """The pure helpers the specification leans on."""

    def test_saturate(self):
        self.assertEqual(tool.saturate(float("nan")), 0)
        self.assertEqual(tool.saturate(float("inf")), 0)
        self.assertEqual(tool.saturate(-3.0), 0)
        self.assertEqual(tool.saturate(2.0 ** 64), tool.MASK[8])
        self.assertEqual(tool.saturate(12.9), 12)

    def test_duration_steps(self):
        self.assertEqual(tool.duration_steps(3600.0), 121)
        self.assertEqual(tool.duration_steps(59.0), 1)
        self.assertEqual(tool.duration_steps(60.0), 3)
        for odd in (-1.0, float("nan"), float("inf"), 0.0):
            self.assertEqual(tool.duration_steps(odd), 1)
        self.assertEqual(tool.duration_steps(1e300), tool.MASK[8])

    def test_round_half_away(self):
        self.assertEqual(tool.round_half_away(2.5), 3.0)
        self.assertEqual(tool.round_half_away(-2.5), -3.0)
        self.assertEqual(tool.round_half_away(2.4999), 2.0)

    def test_five_figures(self):
        self.assertEqual(tool.five_figures(99999), 99999)
        self.assertEqual(tool.five_figures(123456), 123450)
        self.assertEqual(tool.five_figures(49180000001), 49180000000)

    def test_ring_position(self):
        self.assertEqual(tool.phys((5, 3, 4, 1)), 4)
        self.assertEqual(tool.phys((5, 3, 4, 2)), 0)
        self.assertEqual(tool.phys((1, 0, 1, 0)), 0)

    def test_unix_millis(self):
        self.assertEqual(tool.unix_millis((tool.pack_date(1970, 1), 0, 0)), 0)
        self.assertEqual(tool.unix_millis((tool.pack_date(1970, 2), 5, 7000000)), 86400000 + 5007)

    def test_fused_is_exact(self):
        self.assertEqual(tool.fused(0.1, 3.0, -0.30000000000000004), -2.7755575615628914e-17)
        self.assertEqual(tool.fused(0.0, 5.0, 0.0), 0.0)

    def test_expected_bytes_fill(self):
        out = tool.expected_bytes({0: b"\x01"})
        self.assertEqual(len(out), tool.SLICE_SIZE)
        self.assertEqual(out[1], tool.STACK_MARK)


if __name__ == "__main__":
    unittest.main()
