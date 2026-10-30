"""Tests for tools/system_buy_order.py: spot buy cycle and block step of node #94."""

import json
import math
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import system_buy_order as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-system-buy-order-94"
SHARED = {}


def shared():
    if not SHARED:
        SHARED["image"] = tool.load_image()
        SHARED["evidence"] = tool.analyse(SHARED["image"], full=False)
        SHARED["harness"] = tool.Harness(SHARED["image"])
    return SHARED


def kinds(run):
    return [event[0] for event in run["events"]]


def order_of(run):
    return bytes.fromhex(next(event for event in run["events"] if event[0] == "place")[4])


def word(record, at, size=8):
    return int.from_bytes(record[at:at + size], "little")


def state(run, index=0):
    return tool.struct.unpack_from("<dddQ", run["entries"][index])


class IdentityTests(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_hash_constant(self):
        self.assertEqual(tool.SHA256, "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")

    def test_function_extents(self):
        image = shared()["image"]
        self.assertEqual(image.exact_fde(tool.CYCLE), (0x1E83350, 0x1E83E1F))
        self.assertEqual(image.exact_fde(tool.DRIVER), (0x26FED00, 0x26FF186))
        self.assertEqual(image.exact_fde(tool.BEST), (0x23978C0, 0x2397AD3))

    def test_outside_every_fde_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            shared()["image"].exact_fde(tool.CYCLE + 1)

    def test_nobits_never_resolves(self):
        image = shared()["image"]
        bss = image.named[".bss"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            image.offset(bss["address"] + bss["size"] - 8)

    def test_callers_are_pinned(self):
        rows = shared()["evidence"]["callers"]
        self.assertEqual([(row["site"], row["flag"]) for row in rows], [("0x222a0f5", 0), ("0x23e85e8", 1)])

    def test_changed_caller_bytes_fail(self):
        image = shared()["image"]
        at = image.offset(0x222A0F5 - 2)
        blob = bytearray(image.blob)
        blob[at] ^= 1
        broken = tool.Image.__new__(tool.Image)
        broken.__dict__.update(image.__dict__)
        broken.blob = bytes(blob)
        with self.assertRaisesRegex(tool.EvidenceError, "flag bytes differ"):
            tool.check_callers(broken)

    def test_pins_have_their_counts(self):
        rows = shared()["evidence"]["pins"]
        self.assertEqual(len(rows), len(tool.PINS))
        self.assertEqual(len(next(row for row in rows if "user literal" in row["meaning"])["sites"]), 3)

    def test_a_wrong_pin_count_fails(self):
        image = shared()["image"]
        kept = tool.PINS
        try:
            tool.PINS = ((tool.CYCLE, "no such bytes", b"\x90\x90\x90\x90\x90\x90\x90\x90\xf1", 1),)
            with self.assertRaisesRegex(tool.EvidenceError, "has 0 sites"):
                tool.read_pins(image)
        finally:
            tool.PINS = kept

    def test_constants(self):
        constants = shared()["evidence"]["constants"]
        self.assertEqual(constants["f64"], {"0x20a730": 1.0, "0x20a8a8": 10.0, "0x20b080": 1e-15, "0x20a448": -1e-15})
        self.assertEqual(constants["span_name"]["text"], "hyperliquidity_ensure_orders")
        self.assertEqual(constants["elapsed_location"], {"path": "l1/src/time.rs", "line": 84})

    def test_locations_stay_below_the_crate(self):
        for row in shared()["evidence"]["locations"]:
            self.assertFalse(row["path"].startswith("/"), row)
        self.assertEqual(shared()["evidence"]["locations"][0], {"slot": "0x56bb478", "path": "l1/src/books.rs", "line": 19, "column": 47})


class EvaluatorTests(unittest.TestCase):
    def test_no_mismatch(self):
        evidence = shared()["evidence"]
        self.assertEqual(evidence["mismatches"], 0, evidence["first_mismatch"])

    def test_every_outcome_occurs(self):
        outcomes = shared()["evidence"]["cycle_outcomes"]
        self.assertEqual(sorted(outcomes), ["balance short", "gates closed or no key", "order placed", "panic", "price conversion failed"])
        self.assertTrue(all(outcomes.values()))

    def test_network_argument_is_never_read(self):
        self.assertEqual(shared()["evidence"]["argument_differences"], 0)

    def test_most_of_each_function_runs(self):
        for row in shared()["evidence"]["functions"][:2]:
            self.assertGreaterEqual(row["instructions_stepped"] / row["instructions"], 0.9, row)

    def test_a_corrupted_constant_is_seen(self):
        harness = tool.Harness(shared()["image"])
        at = tool.find_all(shared()["image"], tool.CYCLE, b"\x41\xb9\x02\x00\x00\x00")[0]
        harness.machine.patches = {at + 2: 3}
        case = tool.CycleCase("x", [tool.good()], balances=tool.DEFAULT_BALANCES)
        self.assertRegex(tool.compare_cycle(harness, case), "events differs")

    def test_a_wrong_spec_is_seen(self):
        harness = tool.Harness(shared()["image"])
        case = tool.CycleCase("x", [tool.good()], balances=tool.DEFAULT_BALANCES)
        run = harness.run_cycle(case)
        wrong = tool.spec_cycle(tool.CycleCase("x", [tool.good(count=1)], balances=tool.DEFAULT_BALANCES))
        self.assertNotEqual(run["entries"], wrong["entries"])


class CycleTests(unittest.TestCase):
    def run_one(self, entry, **options):
        options.setdefault("balances", tool.DEFAULT_BALANCES)
        return shared()["harness"].run_cycle(tool.CycleCase("t", [entry], **options))

    def test_cancel_comes_first_with_user_flag_and_reason(self):
        run = self.run_one(tool.good())
        self.assertEqual(kinds(run)[0], "cancel")
        self.assertEqual(run["events"][0][2:], ("fe" * 20, 1, tool.EX, tool.EVENTS, 2))

    def test_decay_ignores_elapsed(self):
        run = self.run_one(tool.good(), elapsed={0: 2.5})
        total, weight, window, count = state(run)
        factor = 1.0 - 1.0 / 30.0
        self.assertEqual(total, 2500.0 * 2.5 + factor * 4.0)
        self.assertEqual(weight, 2.5 + factor * 2.0)
        self.assertEqual((window, count), (30.0, 101))

    def test_first_sample_counts_one_second(self):
        run = self.run_one(tool.Entry(count=0))
        self.assertEqual(state(run)[:2], (2500.0, 1.0))
        self.assertEqual(kinds(run), ["cancel"])

    def test_gap_above_window_resets_and_drops_sample(self):
        run = self.run_one(tool.good(window=4.0), elapsed={0: 5.0})
        self.assertEqual(state(run), (0.0, 0.0, 10.0, 0))
        self.assertNotIn("convert", kinds(run))
        self.assertEqual(run["entries"][0][0x20:0x24], bytes(4))

    def test_gap_equal_to_window_does_not_reset(self):
        run = self.run_one(tool.good(), elapsed={0: 30.0})
        self.assertEqual(state(run)[3], 101)

    def test_window_is_not_lifted_on_update(self):
        run = self.run_one(tool.good(window=4.0), elapsed={0: 1.0})
        self.assertEqual(state(run)[2], 4.0)

    def test_count_gate_is_window_over_count(self):
        self.assertNotIn("convert", kinds(self.run_one(tool.good(count=28))))
        self.assertIn("convert", kinds(self.run_one(tool.good(count=29))))

    def test_weight_floor_is_strict(self):
        still = dict(window=1e19, count=tool.MASK[8], total=2e-15)
        self.assertIn("convert", kinds(self.run_one(tool.good(weight=1e-15, **still), elapsed={0: 0.0})))
        self.assertNotIn("convert", kinds(self.run_one(tool.good(weight=tool.f64_below(1e-15), **still), elapsed={0: 0.0})))

    def test_tiny_negative_sum_is_flushed_to_zero(self):
        still = dict(window=1e19, count=tool.MASK[8], weight=2.0)
        run = self.run_one(tool.good(total=tool.f64_above(-1e-15), **still), elapsed={0: 0.0})
        self.assertEqual(next(event for event in run["events"] if event[0] == "convert")[3], 0)
        self.assertNotIn("convert", kinds(self.run_one(tool.good(total=-1e-15, **still), elapsed={0: 0.0})))

    def test_price_is_the_lower_of_mean_and_sample(self):
        still = dict(window=1e19, count=tool.MASK[8], weight=2.0)
        low = self.run_one(tool.good(total=4.0, **still), elapsed={0: 0.0})
        high = self.run_one(tool.good(total=1e9, **still), elapsed={0: 0.0})
        self.assertEqual(tool.to_float(next(event for event in low["events"] if event[0] == "convert")[3]), 2.0)
        self.assertEqual(tool.to_float(next(event for event in high["events"] if event[0] == "convert")[3]), 2500.0)

    def test_cap_equal_passes(self):
        still = dict(window=1e19, count=tool.MASK[8], weight=2.0, total=4.0)
        self.assertIn("convert", kinds(self.run_one(tool.good(cap=2.0, **still), elapsed={0: 0.0})))
        self.assertNotIn("convert", kinds(self.run_one(tool.good(cap=1.5, **still), elapsed={0: 0.0})))

    def test_scale_is_quote_second_byte_minus_base_first_byte(self):
        run = self.run_one(tool.good(), pairs=((0, 1),), tokens=((2, 0xAA), (0xBB, 7)), balances=((1, 1 << 40),))
        self.assertEqual(state(run)[0], 25.0 * 1.0 + (1.0 - 1.0 / 30.0) * 4.0)

    def test_order_record(self):
        run = self.run_one(tool.good(amount=7000001), prices={0: (tool.OK_STATUS, 3000123)}, ticks={0: 100})
        record = order_of(run)
        self.assertEqual(word(record, 0x80), 3000100)
        self.assertEqual(word(record, 8), 2)
        self.assertEqual(word(record, 0x90, 2), 0)
        self.assertEqual(record[0xB8:0xCC], b"\xfe" * 20)
        self.assertEqual(word(record, 0x88), tool.time_millis(tool.NOW))

    def test_limit_never_rounds_to_zero(self):
        run = self.run_one(tool.good(amount=5000), prices={0: (tool.OK_STATUS, 50)}, ticks={0: 100})
        self.assertEqual(word(order_of(run), 0x80), 1)

    def test_balance_is_of_the_quote_token(self):
        pairs = ((0, 1),)
        self.assertIn("place", kinds(self.run_one(tool.good(amount=500), pairs=pairs, balances=((1, 500),))))
        self.assertNotIn("place", kinds(self.run_one(tool.good(amount=500), pairs=pairs, balances=((0, 500),))))

    def test_balance_equal_passes_and_one_short_fails(self):
        self.assertIn("place", kinds(self.run_one(tool.good(amount=500), balances=((1, 500),))))
        self.assertNotIn("place", kinds(self.run_one(tool.good(amount=501), balances=((1, 500),))))

    def test_zero_amount_places_size_zero_with_no_balance(self):
        run = self.run_one(tool.good(amount=0), balances=())
        self.assertEqual(word(order_of(run), 8), 0)

    def test_no_top_key_leaves_state_alone(self):
        entry = tool.good()
        run = self.run_one(entry, books={0: (None, 2510000, 0)})
        self.assertEqual(run["entries"][0], entry.pack())
        self.assertEqual(kinds(run), ["cancel"])

    def test_book_bound_panics_at_books_rs(self):
        run = self.run_one(tool.good(9))
        self.assertEqual(run["stop"], ("panic", tool.LOCATION_BOOKS))
        self.assertEqual(kinds(run), [])

    def test_negative_scale_panics(self):
        run = self.run_one(tool.good(1))
        self.assertEqual(run["stop"], ("overflow", tool.LOCATION_DECIMALS))

    def test_length_past_the_tree_panics_after_the_last_entry(self):
        run = shared()["harness"].run_cycle(tool.CycleCase("t", [tool.good()], claimed=2, balances=tool.DEFAULT_BALANCES))
        self.assertEqual(run["stop"], ("panic", tool.LOCATION_NAVIGATE))
        self.assertIn("place", kinds(run))

    def test_nan_window_skips_the_reset(self):
        run = self.run_one(tool.good(window=math.nan), elapsed={0: 1.0})
        self.assertTrue(math.isnan(state(run)[0]))
        self.assertEqual(state(run)[3], 101)

    def test_order_result_frees(self):
        run = self.run_one(tool.good(), places={0: ("ok", 3, (2, 0, 5))})
        frees = [event for event in run["events"] if event[0] == "free"]
        self.assertEqual([event[2] for event in frees], [3 * 0x228, 16, 40])


class TimeTests(unittest.TestCase):
    def test_epoch(self):
        self.assertEqual(tool.days_from_epoch(1970, 1), 0)
        self.assertEqual(tool.time_millis((tool.pack_date(1970, 2), 1, 2000000)), 86401002)

    def test_before_epoch_clamps(self):
        self.assertEqual(tool.time_millis((tool.pack_date(1969, 365), 0, 0)), 0)
        self.assertEqual(tool.time_millis((tool.pack_date(-5, 1), 0, 0)), 0)

    def test_leap_years(self):
        self.assertEqual(tool.days_from_epoch(2001, 1) - tool.days_from_epoch(2000, 1), 366)
        self.assertEqual(tool.days_from_epoch(2101, 1) - tool.days_from_epoch(2100, 1), 365)


class DriverTests(unittest.TestCase):
    def run_one(self, **options):
        return shared()["harness"].run_driver(tool.DriverCase("t", **options))

    def test_gate_stops_everything(self):
        run = self.run_one(gate=1, markets=((3, 5 << 30),))
        self.assertEqual(run["events"], [])

    def test_floor(self):
        for balance, amount in ((tool.TRANSFER_FLOOR + 1, 1), (tool.TRANSFER_FLOOR, 0), (5, 0)):
            run = self.run_one(markets=((3, balance),))
            self.assertEqual(next(event for event in run["events"] if event[0] == "transfer")[6], amount)

    def test_transfer_runs_at_zero_amount(self):
        self.assertIn("transfer", kinds(self.run_one(markets=((3, 0),))))

    def test_empty_tree_skips_the_sweep(self):
        self.assertNotIn("transfer", kinds(self.run_one(tree=0, markets=((3, 5 << 30),))))

    def test_all_balances_are_read_before_any_transfer(self):
        names = kinds(self.run_one(markets=((3, 1), (4, 1))))
        self.assertEqual(names[:5], ["alloc", "balance", "balance", "transfer", "transfer"])

    def test_flag_skips_the_bucket(self):
        run = self.run_one(flag=1, last=7)
        self.assertEqual(run["last"], 7)
        self.assertIn("ensure", kinds(run))
        self.assertNotIn("span", kinds(run))

    def test_bucket_rolls_only_upward(self):
        now = tool.time_millis(tool.NOW) // 86400000
        self.assertEqual(self.run_one(last=now - 1)["last"], now)
        same = self.run_one(last=now)
        self.assertEqual(same["last"], now)
        self.assertEqual(next(event for event in same["events"] if event[0] == "span")[3], 0)
        self.assertEqual(self.run_one(last=now + 1)["last"], now + 1)

    def test_span_runs_before_the_cycle(self):
        names = kinds(self.run_one())
        self.assertLess(names.index("span"), names.index("cycle"))
        self.assertEqual(names[-1], "flush")

    def test_events_reach_the_flush(self):
        run = self.run_one()
        self.assertEqual(run["events"][-1], ("flush", tool.DRIVER_VEC, tool.EX))

    def test_allocation_failure(self):
        run = self.run_one(markets=((3, 1), (4, 1)), alloc_fails=True)
        self.assertEqual(run["stop"], ("alloc failed", 8, 32))


class OutputTests(unittest.TestCase):
    def test_mutation_targets_cover_each_kind(self):
        image = shared()["image"]
        rows = tool.decode_range(image, *image.exact_fde(tool.CYCLE))
        found = {kind for _, _, kind in tool.mutation_targets(image, rows)}
        self.assertEqual(found, {"branch", "cmov", "immediate", "offset", "set"})

    def test_short_branch_mutation_flips_the_condition(self):
        image = shared()["image"]
        rows = tool.decode_range(image, *image.exact_fde(tool.CYCLE))
        row = next(item for item in rows if item.op == "jcc" and item.size == 2)
        patch = tool.mutate_patch(image, row.va, row.size - 2)
        self.assertEqual(list(patch), [row.va])
        self.assertEqual(patch[row.va] ^ image.blob[image.offset(row.va)], 1)

    def test_committed_evidence_matches_a_quick_run(self):
        committed = json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))
        evidence = {key: value for key, value in shared()["evidence"].items() if not key.startswith("_") and key != "mutations"}
        for key in evidence:
            if key != "instructions_stepped":
                self.assertEqual(json.loads(json.dumps(evidence[key])), committed[key], key)

    def test_every_survivor_has_a_reason(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]]
        self.assertTrue(rows)
        for row in rows:
            if row[3] != "killed":
                self.assertTrue(row[5], row)

    def test_render_is_deterministic(self):
        evidence = shared()["evidence"]
        self.assertEqual(tool.render(evidence), tool.render(evidence))
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, tool.render(evidence))
            self.assertEqual(sorted(path.name for path in pathlib.Path(folder).iterdir()), ["call_sites.tsv", "evidence.json", "mutations.tsv"])


if __name__ == "__main__":
    unittest.main()
