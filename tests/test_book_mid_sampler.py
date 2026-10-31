"""Tests for tools/book_mid_sampler.py: book mid sampler of node #94."""

import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import book_mid_sampler as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-book-mid-sampler-94"
SHARED = {}
Book, Case, Side = tool.Book, tool.Case, tool.Side


def shared():
    if not SHARED:
        SHARED["image"] = tool.load_image()
        SHARED["harnesses"] = [tool.Harness(SHARED["image"], copy) for copy in tool.COPIES]
    return SHARED


def run(case, copy=0):
    return shared()["harnesses"][copy].run(case)


def samples(result):
    return [(event[1], struct.unpack("<d", bytes.fromhex(event[2]))[0]) for event in result["events"] if event[0] == "sample"]


def status(result):
    return [event for event in result["events"] if event[0] == "status step"][0]


def setUpModule():
    shared()


class IdentityTests(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_hash_constant(self):
        self.assertEqual(tool.SHA256, "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")

    def test_function_extents(self):
        image = shared()["image"]
        self.assertEqual(image.exact_fde(0x4CDF580), (0x4CDF580, 0x4CDFDF7))
        self.assertEqual(image.exact_fde(0x4CDFE00), (0x4CDFE00, 0x4CE0677))
        self.assertEqual(image.exact_fde(0x26F8D50), (0x26F8D50, 0x26F95C7))
        self.assertEqual(image.exact_fde(0x32780D0), (0x32780D0, 0x32781B7))

    def test_inside_a_function_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            shared()["image"].exact_fde(0x4CDF581)

    def test_nobits_never_resolves(self):
        image = shared()["image"]
        bss = image.named[".bss"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            image.offset(bss["address"] + 8)

    def test_texts_and_pair(self):
        constants = tool.read_constants(shared()["image"])
        self.assertEqual(constants["status_text"]["bytes"], "action_delayer_log_status")
        self.assertEqual(constants["sample_text"]["bytes"], "deterministic_vty_alert_n_bucket_samples")
        self.assertEqual(constants["status_pair"]["values"], [0.01, 0.05])

    def test_a_wrong_text_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "text at"):
            tool.read_text(shared()["image"], tool.STATUS_NAME, b"action_delayer_log_statuz")

    def test_edges_are_real_calls(self):
        self.assertEqual(len(tool.check_edges(shared()["image"])), 5)

    def test_a_wrong_edge_is_refused(self):
        image = shared()["image"]
        saved = tool.COPIES
        tool.COPIES = (dict(tool.COPIES[0], drain=0x286F7E0),)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "misses"):
                tool.check_edges(image)
        finally:
            tool.COPIES = saved

    def test_pin_count_is_enforced(self):
        image = shared()["image"]
        saved = tool.pin_rows
        tool.pin_rows = lambda: [(0x4CDF580, "absent", b"\xde\xad\xbe\xef\x01", 1)]
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "sites"):
                tool.read_pins(image)
        finally:
            tool.pin_rows = saved

    def test_pins_hold(self):
        self.assertEqual(len(tool.read_pins(shared()["image"])), len(tool.pin_rows()))

    def test_hosts(self):
        rows = tool.read_hosts(shared()["image"])
        self.assertEqual([(row["site"], row["host"]) for row in rows], [("0x470f7a5", "0x470e9a0"), ("0x47172fa", "0x47162d0"), ("0x222a615", "0x22297c0")])

    def test_a_wrong_host_is_refused(self):
        image = shared()["image"]
        saved = tool.HOSTS
        tool.HOSTS = ((0x4CDF580, 0x470F7A6, 0x470E9A0, 0x4CDF335, 0x4CDF180),)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "call sites"):
                tool.read_hosts(image)
        finally:
            tool.HOSTS = saved

    def test_copies_have_one_shape(self):
        rows = tool.copy_diff(shared()["image"])
        self.assertEqual([row["shape_differences"] for row in rows], [0, 0])
        self.assertEqual(rows[0]["field_map"]["0x3370"], "0x3df0")
        self.assertEqual(rows[1]["field_map"], {})

    def test_sample_slot_is_the_writer(self):
        relative = shared()["harnesses"][0].relative
        self.assertEqual(relative[tool.SLOT_SAMPLE], tool.SAMPLE_WRITER)


class PriceTests(unittest.TestCase):
    def test_every_copy_matches_the_specification_on_a_sample(self):
        case = Case("mix", perps=[Book([-99], [101]), Book()], states=[1, 2], assets=[2, 1], spots=[Book([-8], [12])])
        for index, copy in enumerate(tool.COPIES):
            self.assertIsNone(tool.compare_run(shared()["harnesses"][index], case), copy["name"])

    def test_mean_is_floored(self):
        result = run(Case("odd", perps=[Book([-3], [4])], assets=[6], states=[1]))
        self.assertEqual(samples(result), [(0, 3.0)])

    def test_mean_does_not_overflow(self):
        huge = 1 << 63
        result = run(Case("huge", spots=[Book([-(huge - 1)], [huge - 1])], tokens=[(0, 0), (0, 0)]))
        self.assertEqual(samples(result), [(10000, float(huge - 1))])

    def test_i64_min_stays_positive(self):
        self.assertEqual(tool.abs64(-(1 << 63)), 1 << 63)
        self.assertEqual(tool.abs64(-5), 5)
        self.assertEqual(tool.abs64(5), 5)

    def test_perp_scale(self):
        result = run(Case("scale", perps=[Book([-100], [100])], assets=[4], states=[1]))
        self.assertEqual(samples(result), [(0, 1.0)])

    def test_spot_scale_is_quote_wei_minus_base_sz(self):
        result = run(Case("spot", spots=[Book([-500], [500])], pairs=[(1, 0)], tokens=[(9, 7), (5, 0)]))
        self.assertEqual(samples(result), [(10000, 5.0)])

    def test_perp_without_a_mid_takes_the_state_price(self):
        result = run(Case("state", perps=[Book([-10], [])], assets=[6], states=[77]))
        self.assertEqual(samples(result), [(0, 77.0)])

    def test_the_halted_set_changes_nothing(self):
        plain = run(Case("plain", perps=[Book(), Book()], states=[5, 6]))
        halted = run(Case("halted", perps=[Book(), Book()], states=[5, 6], halted=(0, 1)))
        self.assertEqual(plain["events"], halted["events"])

    def test_spot_fallback_is_a_median(self):
        result = run(Case("median", spots=[Book([7], [], last=20)], tokens=[(0, 0), (0, 0)]))
        self.assertEqual(samples(result), [(10000, 13.0)])
        result = run(Case("no tops", spots=[Book(last=20)], tokens=[(0, 0), (0, 0)]))
        self.assertEqual(samples(result), [(10000, 20.0)])

    def test_spot_median_of_two_with_last_zero(self):
        result = run(Case("zero last", spots=[Book([7], [], last=0)], tokens=[(0, 0), (0, 0)]))
        self.assertEqual(samples(result), [(10000, 3.0)])

    def test_fallback_uses_the_book_of_the_index(self):
        # Book 0 is empty and names book 1; book 1 writes under index 2, so key 10001 keeps book 0's fallback.
        result = run(Case("target", spots=[Book(index=1), Book([-40], [60], last=9, index=2), Book([-5], [7])], tokens=[(0, 0)] * 4))
        self.assertEqual(samples(result), [(10001, 40.0), (10002, 6.0)])

    def test_direct_fallback_sorts_three_values(self):
        for bid, ask, last in ((3, 5, 4), (5, 4, 3), (4, 3, 5)):
            result = run(Case("direct", spots=[Book([bid], [ask], last=last)], direct=True))
            self.assertEqual(result["events"], [("fallback", 4)])

    def test_later_book_of_one_index_wins(self):
        result = run(Case("twice", spots=[Book([-10], [20], index=1), Book([-30], [40])], tokens=[(0, 0)] * 3))
        self.assertEqual(samples(result), [(10001, 35.0)])


class KeyTests(unittest.TestCase):
    def test_dex_shift(self):
        result = run(Case("dex", perps=tool.wide(2), dex=2))
        self.assertEqual([key for key, _ in samples(result)], [120000, 120001])

    def test_key_past_the_limit_collapses(self):
        result = run(Case("big dex", perps=tool.wide(2), dex=9990))
        self.assertEqual([key for key, _ in samples(result)], [tool.KEY_NONE])

    def test_outcome_key(self):
        result = run(Case("outcome", spots=tool.wide(1), pairs=[(3, 1)], tokens=[(1, 8)] * 4, outcomes={3: (7, 1)}))
        self.assertEqual([key for key, _ in samples(result)], [100000071])

    def test_order_is_by_key_and_map_splits(self):
        result = run(Case("many", perps=tool.wide(40), spots=tool.wide(14, 7)))
        keys = [key for key, _ in samples(result)]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(keys), 54)

    def test_only_the_first_vector_entry_is_read(self):
        plain = run(Case("one", perps=tool.wide(2)))
        more = run(Case("three", perps=tool.wide(2), perp_vector=3, meta_vector=2))
        self.assertEqual(plain["events"], more["events"])


class BucketTests(unittest.TestCase):
    def test_exact_millis(self):
        now = (tool.pack_date(2026, 303, 7), 3600, 250000000)
        self.assertEqual(run(Case("ms", now=now, bucket=1))["seen"], tool.unix_millis(now))

    def test_unix_millis_against_datetime(self):
        import datetime
        start = datetime.datetime(1970, 1, 1)
        for year, ordinal in ((1970, 1), (2024, 366), (2101, 1), (1600, 60), (1, 1)):
            moment = datetime.datetime(year, 1, 1) + datetime.timedelta(days=ordinal - 1)
            expected = max(0, (moment - start).days * 86400000)
            self.assertEqual(tool.unix_millis((tool.pack_date(year, ordinal), 0, 0)), expected)

    def test_flag_only_above_the_seen_bucket(self):
        now = (tool.pack_date(2026, 303), 0, 0)
        bucket = tool.unix_millis(now) // 1000
        self.assertEqual(status(run(Case("above", now=now, bucket=1000, seen=bucket - 1)))[4], 1)
        self.assertEqual(status(run(Case("equal", now=now, bucket=1000, seen=bucket)))[4], 0)
        self.assertEqual(run(Case("below", now=now, bucket=1000, seen=bucket + 1))["seen"], bucket + 1)

    def test_network_byte_passes_through(self):
        self.assertEqual(status(run(Case("net", network=2)))[5], 2)

    def test_width_exactly_two_to_the_32(self):
        result = run(Case("width", now=(tool.pack_date(1970, 2), 1, 0), bucket=1 << 32))
        self.assertEqual(result["seen"], 0)

    def test_status_text_and_length(self):
        event = status(run(Case("text")))
        self.assertEqual(event[1:3], (tool.STATUS_NAME, 25))


class PanicTests(unittest.TestCase):
    def test_no_vectors(self):
        self.assertEqual(run(Case("a", no_perps=True))["stop"], ("unwrap", 0x141, tool.LOC_PERPS))
        self.assertEqual(run(Case("b", no_metas=True))["stop"], ("unwrap", 0x141, tool.LOC_METAS))

    def test_state_row_bound(self):
        stop = run(Case("c", perps=[Book(), Book()], states=[5]))["stop"]
        self.assertEqual(stop[:3], ("bounds", 1, 1))

    def test_book_past_asset_rows(self):
        self.assertEqual(run(Case("d", perps=tool.wide(3), assets=[1, 2], states=[1, 2, 3]))["stop"], ("panic", tool.LOC_ASSET))

    def test_decimals_limit(self):
        self.assertIsNone(run(Case("e", perps=tool.wide(1), assets=[6], states=[1]))["stop"])
        self.assertEqual(run(Case("f", perps=tool.wide(1), assets=[7], states=[1]))["stop"], ("sub overflow", tool.LOC_SZ))

    def test_quote_wei_below_base_sz(self):
        self.assertEqual(run(Case("g", spots=tool.wide(1), pairs=[(1, 0)], tokens=[(0, 2), (3, 0)]))["stop"], ("sub overflow", tool.LOC_DECIMALS))

    def test_spot_past_pairs(self):
        self.assertEqual(run(Case("h", spots=tool.wide(2), pairs=[(0, 1)]))["stop"], ("bounds", 1, 1, tool.LOC_PAIR))

    def test_hollow_leaf_with_no_key_above(self):
        self.assertEqual(run(Case("i", perps=[Book(Side(hollow=(1, None)), [5])]))["stop"], ("panic", tool.LOC_TOP))


class ControlTests(unittest.TestCase):
    def test_the_comparison_sees_a_wrong_price(self):
        harness = shared()["harnesses"][0]
        image = shared()["image"]
        harness.machine.patches = tool.mutate_patch(image, 0x4CDF71E, 2, "immediate")
        harness.machine.cache.pop(0x4CDF71E, None)
        try:
            self.assertIsNotNone(tool.compare_run(harness, Case("dex", perps=tool.wide(2), dex=2)))
        finally:
            harness.machine.patches = {}
            harness.machine.cache.pop(0x4CDF71E, None)

    def test_a_wrong_expected_value_is_seen(self):
        harness = shared()["harnesses"][0]
        case = Case("x", perps=tool.wide(1))
        saved = tool.perp_key
        tool.perp_key = lambda raw: raw + 1
        try:
            self.assertIsNotNone(tool.compare_run(harness, case))
        finally:
            tool.perp_key = saved


class PacketTests(unittest.TestCase):
    def test_tool_writes_the_stored_static_rows(self):
        image = shared()["image"]
        doc = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(doc["pins"], tool.read_pins(image))
        self.assertEqual(doc["hosts"], tool.read_hosts(image))
        self.assertEqual(doc["copy_diff"], tool.copy_diff(image))
        self.assertEqual(doc["mismatches"], 0)

    def test_no_silent_survivor(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertTrue(rows)
        self.assertEqual([row for row in rows if row[3] != "killed" and not row[5]], [])

    def test_write_outputs_round_trip(self):
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, {"a.txt": "x\n"})
            self.assertEqual((pathlib.Path(folder) / "a.txt").read_text(), "x\n")

    def test_no_external_tool_is_called(self):
        source = (ROOT / "tools" / "book_mid_sampler.py").read_text()
        self.assertNotIn("subprocess", source)


if __name__ == "__main__":
    unittest.main()
