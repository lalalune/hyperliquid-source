import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vault_split_body115 as vs  # noqa: E402

M64 = vs.M64
KEYS = vs.KEYS


def bits(value):
    return vs.to_bits(value)


def case(**changes):
    """The clean ring case with some fields replaced."""
    fields = dict(store="ring", items={KEYS[3]: (bits(0.9), 5000, 4000)}, cap=2, head=1, height=0, chunks=[], tag=2, set_keys=[KEYS[1], KEYS[5]],
                  set_count=2, set_height=0, set_chunks=[], key=KEYS[3], vault=KEYS[0], leader=KEYS[7], rate=bits(0.1), ratio=bits(0.25),
                  limit=100000000, other=5, ctx=(vs.LEDGER, 11, 22), amounts={KEYS[0]: 4000000, KEYS[1]: 3000000, KEYS[5]: 1000000},
                  default_amount=0, balances=(1000000, 1000000), lazy=0, effect="none", rewrite=(0, 0), counter=10 ** 9)
    fields.update(changes)
    return vs.Case(name="t", **fields)


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = vs.F.load_image()
        cls.sites = vs.locations(cls.image)
        for name, va in vs.EVENT_SITES.items():
            vs.LOCATION[name] = cls.sites[va]
        cls.harness = vs.Harness(cls.image)

    def run_both(self, c):
        return vs.run_case(self.harness, c), vs.spec(c)

    def outcome(self, c):
        got, expected = self.run_both(c)
        self.assertEqual(got, expected)
        return got


class TestImage(unittest.TestCase):
    def test_digest_is_pinned(self):
        self.assertEqual(vs.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        with self.assertRaises(vs.EvidenceError):
            vs.F.load_image(vs.BINARY, "0" * 64)

    def test_subject_extents(self):
        image = vs.F.load_image()
        self.assertEqual(image.exact_fde(vs.ENTRY), (0x44AF2F0, 0x44B04B6))
        self.assertEqual(image.exact_fde(vs.SEARCH)[1] - vs.SEARCH, 0x1EC)
        with self.assertRaises(vs.EvidenceError):
            image.exact_fde(vs.ENTRY + 1)

    def test_decoder_covers_the_body_exactly(self):
        image = vs.F.load_image()
        rows = vs.F.decode_range(image, *image.exact_fde(vs.ENTRY))
        self.assertEqual(len(rows), 954)
        self.assertEqual(rows[-1].next, vs.ENTRY_END)
        with self.assertRaises(vs.EvidenceError):
            vs.F.decode_range(image, vs.ENTRY, vs.ENTRY_END - 1)

    def test_extended_forms_decode(self):
        image = vs.F.load_image()
        ops = {row.va: row.op for row in vs.F.decode_range(image, *image.exact_fde(vs.ENTRY))}
        self.assertEqual(ops[0x44AFFF0], "punpcklqdq")     # unpcklpd, same bits
        self.assertEqual(ops[0x44B00CD], "movhpd")
        self.assertEqual(ops[0x44AF8B7], "cmppd")
        self.assertEqual(ops[0x44AF8BC], "cmppd")

    def test_constants_are_read_from_the_bytes(self):
        rows = {row[1]: row for row in vs.constant_rows(self.image())}
        self.assertEqual(rows["scale"][3], "1000000.0")
        self.assertEqual(rows["tiny"][3], "1e-15")
        self.assertEqual(rows["minus_tiny"][3], "-1e-15")
        self.assertEqual(rows["infinity"][3], "inf")
        self.assertEqual(rows["cast_floor"][3], "-9.223372036854776e+18")
        self.assertEqual(rows["cast_ceiling"][3], "9.223372036854776e+18")

    @staticmethod
    def image():
        return vs.F.load_image()


class TestEventSites(Fixture):
    def test_fifteen_sites_in_three_location_families(self):
        self.assertEqual(len(self.sites), 15)
        self.assertEqual(sorted(self.sites), sorted(vs.EVENT_SITES.values()))
        self.assertEqual(sorted(set(self.sites.values())), [0x648B9C0, 0x648BA50, 0x6493598, 0x64935E0, 0x64935F8])
        self.assertEqual(len(set(self.sites.values())), 5)

    def test_locations_name_distinct_source_positions(self):
        rows = vs.site_rows(self.image, self.sites)
        positions = {(row[3], row[4], row[5]) for row in rows}
        self.assertEqual(sorted(positions), [("l1/src/qtys/impl_ntl.rs", 26, 1), ("l1/src/qtys/impl_ntl.rs", 70, 1), ("l1/src/qtys/mod.rs", 834, 1)])
        by_name = {row[0]: row[3] for row in rows}
        for name in ("acc", "round", "credit_leader", "credit_depositor"):
            self.assertTrue(by_name[name].endswith("mod.rs"), name)
        for name in ("cut", "rest", "diff", "diff_again", "after", "keep", "slot3", "gap", "gap2", "debit", "units"):
            self.assertTrue(by_name[name].endswith("impl_ntl.rs"), name)
        for row in rows:
            self.assertGreater(row[4], 0)

    def test_every_event_site_is_a_call_through_the_slot(self):
        rows = {row.va: row for row in vs.F.decode_range(self.image, *self.image.exact_fde(vs.ENTRY))}
        for va in self.sites:
            self.assertEqual(rows[va].op, "calli")
            self.assertEqual(rows[va].a[4], vs.SLOT_EVENT)

    def test_slot_relocation_closure(self):
        relative = self.image.relative()
        expected = {vs.SLOT_EVENT: 0x4524E40, vs.SLOT_BAL: 0x446BDD0, vs.SLOT_DEBIT: 0x447DB40, vs.SLOT_LAZY: 0x5C87D50,
                    vs.SLOT_PANIC: 0x1680C10, vs.SLOT_PANIC_LEN: 0x1680C30}
        for slot, target in expected.items():
            self.assertEqual(relative[slot], target)
        self.assertNotIn(vs.SLOT_MEMCMP, relative)      # memcmp is bound by a symbol relocation, not a RELATIVE one


class TestScalarRules(unittest.TestCase):
    """The float and integer rules, checked on literals without the binary."""

    def test_cast_saturates(self):
        self.assertEqual(vs.f2i(0.0), 0)
        self.assertEqual(vs.f2i(2.9), 2)
        self.assertEqual(vs.f2i(-2.9), -2)
        self.assertEqual(vs.f2i(1e30), vs.MAX64)
        self.assertEqual(vs.f2i(-1e30), vs.MIN64)
        self.assertEqual(vs.f2i(9223372036854775807.0), vs.MAX64)
        self.assertEqual(vs.f2i(-9223372036854775808.0), vs.MIN64)

    def test_cast_sends_nonfinite_to_zero(self):
        self.assertEqual(vs.f2i(float("nan")), 0)
        self.assertEqual(vs.f2i(float("inf")), 0)
        self.assertEqual(vs.f2i(float("-inf")), 0)

    def test_cast_variants_differ(self):
        self.assertEqual(vs.cast(2.5, frozenset(("cast_rounds_to_nearest",))), 2)
        self.assertEqual(vs.cast(2.6, frozenset(("cast_rounds_to_nearest",))), 3)
        self.assertEqual(vs.cast(float("inf"), frozenset(("cast_inf_saturates",))), vs.MAX64)
        self.assertEqual(vs.cast(float("inf"), frozenset()), 0)

    def test_wrap(self):
        self.assertEqual(vs.wrap64(vs.MAX64 + 1), vs.MIN64)
        self.assertEqual(vs.wrap64(vs.MIN64 - 1), vs.MAX64)
        self.assertEqual(vs.wrap64(5), 5)

    def test_unsigned_float_conversion(self):
        self.assertEqual(vs.ufloat(-1), 18446744073709551616.0)
        self.assertEqual(vs.ufloat(7), 7.0)

    def test_lcg_is_deterministic(self):
        first = [next(vs.lcg(5)) for _ in range(3)]
        again = [next(vs.lcg(5)) for _ in range(3)]
        self.assertEqual(first, again)
        stream = vs.lcg(5)
        self.assertNotEqual(next(stream), next(stream))

    def test_key_pool_is_sorted_and_distinct(self):
        self.assertEqual(len(KEYS), 14)
        self.assertEqual(KEYS, sorted(set(KEYS)))
        self.assertTrue(all(len(key) == 20 for key in KEYS))


class TestRuleList(unittest.TestCase):
    """Hand computed expectations of the rule list; the binary is checked against the same numbers below."""

    def test_clean_split(self):
        outcome, log, memory = vs.spec(case(), frozenset()) if vs.LOCATION else (None, None, None)
        if outcome is None:
            self.skipTest("locations not loaded")
        self.assertEqual(outcome[0], "ok")
        credits = [entry for entry in log if entry[0] == "credit"]
        self.assertEqual([entry[3] for entry in credits], [99930, 900070])
        debit = [entry for entry in log if entry[0] == "debit"][0]
        self.assertEqual(debit[3], 1000000)
        apply = [entry for entry in log if entry[0] == "apply"][0]
        self.assertEqual(apply[2:5], (-1000000, 8000000, 5))
        self.assertEqual(memory, (10 ** 9 - 1000000 + 99930 + 900070, ((4306, -896070),)))


class TestBodyOnNamedCases(Fixture):
    def test_clean_split_ring_and_tree_agree(self):
        ring = self.outcome(case())
        tree = self.outcome(case(store="tree"))
        self.assertEqual(ring[0], tree[0])
        self.assertEqual(ring[0][0], "ok")

    def test_clean_split_numbers(self):
        outcome, log, memory = self.outcome(case())
        credits = [entry for entry in log if entry[0] == "credit"]
        self.assertEqual([entry[3] for entry in credits], [99930, 900070])
        self.assertEqual(credits[0][2], KEYS[7])
        self.assertEqual(credits[1][2], KEYS[3])
        self.assertEqual(memory[0], 10 ** 9 - 1000000 + 99930 + 900070)
        fields = dict(outcome[1])
        self.assertEqual(struct.unpack("<Q", fields[0])[0], vs.TAG_OK)
        self.assertEqual(struct.unpack("<q", fields[0xB0][:8])[0], 900070)
        self.assertEqual(struct.unpack("<Q", fields[0xB0][8:])[0], vs.TAG_SOME)
        self.assertEqual(fields[0x30], KEYS[0])
        self.assertEqual(fields[0x44], KEYS[3])
        self.assertEqual(fields[0xC8], KEYS[7])

    def test_set_members_are_summed_in_key_order(self):
        members = [KEYS[1], KEYS[4], KEYS[5], KEYS[11]]
        amounts = {KEYS[0]: 4000000, KEYS[1]: 1, KEYS[4]: 2, KEYS[5]: 3, KEYS[11]: 4}
        for height in (0, 1):
            _, log, _ = self.outcome(case(set_keys=members, set_count=4, amounts=amounts, set_height=height, set_chunks=[2]))
            asked = [entry[2] for entry in log if entry[0] == "amount"]
            self.assertEqual(asked, [KEYS[0]] + members)

    def test_other_tags_skip_the_set(self):
        for tag in (0, 1, 3):
            _, log, _ = self.outcome(case(tag=tag))
            self.assertEqual(len([entry for entry in log if entry[0] == "amount"]), 1)

    def test_count_limits_the_walk(self):
        _, log, _ = self.outcome(case(set_count=1))
        self.assertEqual(len([entry for entry in log if entry[0] == "amount"]), 2)

    def test_count_past_the_set_panics_at_the_parent_check(self):
        outcome, _, _ = self.outcome(case(set_count=3))
        self.assertEqual(outcome, ("panic", 0x44B01A5))

    def test_missing_key_is_the_empty_variant(self):
        outcome, log, memory = self.outcome(case(key=KEYS[9]))
        self.assertEqual(outcome, ("none",))
        self.assertEqual(memory[0], 10 ** 9)
        self.assertEqual([entry[0] for entry in log].count("debit"), 0)

    def test_negative_units_panic(self):
        outcome, _, _ = self.outcome(case(items={KEYS[3]: (bits(0.9), -1, 4000)}))
        self.assertEqual(outcome, ("panic", 0x44B04A1))

    def test_second_balance_smaller_is_the_0x34_error(self):
        outcome, log, memory = self.outcome(case(balances=(1000000, 999999)))
        self.assertEqual(outcome, ("error",))
        self.assertEqual(log[-1], ("error", 0x34))
        self.assertEqual(memory[0], 10 ** 9)

    def test_balance_covering_the_cut_keeps_the_ratio_branch(self):
        outcome, log, _ = self.outcome(case(balances=(3000000, 3000000)))
        self.assertEqual(outcome[0], "ok")

    def test_zero_balance_takes_the_nonpositive_gap_branch(self):
        outcome, log, _ = self.outcome(case(balances=(0, 0)))
        self.assertEqual(outcome[0], "ok")
        self.assertEqual([entry for entry in log if entry[0] == "debit"][0][3], 0)

    def test_lazy_word_adds_two_calls(self):
        _, log, _ = self.outcome(case(lazy=1))
        self.assertEqual([entry for entry in log if entry[0] == "lazy"], [("lazy", 0x44AF98D), ("lazy", 0x44B027E)])

    def test_drop_effect_panics_at_the_second_lookup(self):
        for store in ("ring", "tree"):
            outcome, _, memory = self.outcome(case(store=store, effect="drop"))
            self.assertEqual(outcome, ("panic", 0x44B04AE))
            self.assertEqual(memory[1], ())

    def test_rewrite_effect_changes_the_units_used(self):
        base = self.outcome(case())
        changed = self.outcome(case(effect="rewrite", rewrite=(2, 9)))
        self.assertNotEqual(base[2], changed[2])
        self.assertIn(("event", 0x44AFE13, 0x6493598), changed[1])

    def test_rekey_reads_the_key_again(self):
        two = {KEYS[3]: (bits(0.9), 5000, 4000), KEYS[6]: (bits(0.8), 300, 9)}
        for store in ("ring", "tree"):
            outcome, log, memory = self.outcome(case(items=two, store=store, effect="rekey", rekey=KEYS[6]))
            self.assertEqual(outcome[0], "ok")
            self.assertEqual([entry for entry in log if entry[0] == "credit"][-1][2], KEYS[6])
            missing = self.outcome(case(items=two, store=store, effect="rekey", rekey=KEYS[9]))
            self.assertEqual(missing[0], ("panic", 0x44B04AE))

    def test_min_and_max_cast(self):
        for amount in (vs.MIN64, vs.MAX64):
            self.outcome(case(amounts={KEYS[0]: amount}, set_keys=[], set_count=0, ratio=bits(1.5), items={KEYS[3]: (bits(2.0), 5000, 4000)},
                              balances=(1 << 62, 1 << 62)))

    def test_deep_sets(self):
        wide = [b"\x07" * 18 + index.to_bytes(2, "big") for index in range(255)]
        for count in (255, 129, 256):
            outcome, log, _ = self.outcome(case(set_keys=wide, set_count=count, set_height=8, set_shape=vs.complete_shape(wide, 8)))
            self.assertEqual(len([entry for entry in log if entry[0] == "amount"]), 1 + min(count, 255))
            if count == 256:
                self.assertEqual(outcome, ("panic", 0x44B01A5))

    def test_overflow_events_in_the_sum(self):
        _, log, _ = self.outcome(case(amounts={KEYS[0]: vs.MAX64, KEYS[1]: 5, KEYS[5]: 5}))
        self.assertEqual([entry[1] for entry in log if entry[0] == "event"][:2], [0x44AF602, 0x44AF602])

    def test_ring_wraps_around_the_buffer(self):
        items = {KEYS[2]: (bits(0.5), 1, 1), KEYS[3]: (bits(0.9), 5000, 4000), KEYS[8]: (bits(0.4), 3, 3)}
        for head in range(4):
            self.outcome(case(items=items, cap=4, head=head))

    def test_tree_heights(self):
        items = {KEYS[i]: (bits(0.9), 5000 + i, i) for i in range(1, 13)}
        for height, chunks in ((1, []), (1, [2]), (2, [3, 2, 2]), (2, [])):
            self.outcome(case(items=items, store="tree", height=height, chunks=chunks))


class TestCrafted(Fixture):
    """One crafted case per rule; every expectation below is a literal worked out from the rule list by hand."""

    def events(self, c):
        return [entry[1] for entry in self.outcome(c)[1] if entry[0] == "event"]

    def calls(self, c, kind):
        return [entry for entry in self.outcome(c)[1] if entry[0] == kind]

    def test_clean_case_intermediate_values(self):
        # total 8e6, cut 2e6, base 2e6, balance 1e6, g = 0.25 * 0.5, q = g / 0.9, units = 694
        outcome, log, memory = self.outcome(case())
        self.assertEqual(memory[1], ((4306, -896070),))
        fields = dict(outcome[1])
        self.assertEqual(struct.unpack("<dd", fields[8]), (100.0, 0.09993))
        self.assertEqual(struct.unpack("<dd", fields[0x18]), (98.0, 0.000694))
        self.assertEqual(struct.unpack("<d", fields[0x28])[0], 0.90007)

    def test_apply_receives_the_adjusted_ratio(self):
        # the input rate would give -2000000; the body passes -cast(g * total) with g = rate * balance / base
        apply = self.calls(case(), "apply")[0]
        self.assertEqual(apply[2], -1000000)
        self.assertEqual(apply[3], 8000000)
        apply = self.calls(case(balances=(0, 0)), "apply")[0]
        self.assertEqual(apply[2], 0)

    def test_nonpositive_gap_passes_the_input_rate(self):
        apply = self.calls(case(balances=(2000000, 2000000)), "apply")[0]
        self.assertEqual(apply[2], -2000000)

    def test_sum_saturates_and_fires_the_add_site_once_per_overflow(self):
        sites = self.events(case(amounts={KEYS[0]: vs.MAX64, KEYS[1]: 5, KEYS[5]: 7}))
        self.assertEqual(sites[:2], [0x44AF602, 0x44AF602])

    def test_apply_sees_the_saturated_total(self):
        apply = self.calls(case(amounts={KEYS[0]: vs.MAX64, KEYS[1]: 5, KEYS[5]: 7}), "apply")
        if apply:
            self.assertEqual(apply[0][3], vs.MAX64)

    def test_negative_balance_overflows_the_gap_and_fires_it_twice(self):
        c = case(balances=(vs.MIN64, vs.MIN64))
        sites = self.events(c)
        self.assertEqual(sites[:2], [0x44B0189, 0x44B01C2])      # the wrapped sum stays in range here, so no `round` event
        self.assertNotIn(0x44B020C, sites)

    def test_tiny_negative_ratio_is_treated_as_zero(self):
        outcome, log, memory = self.outcome(case(ratio=bits(-1e-16), balances=(0, 0)))
        self.assertEqual(outcome[0], "ok")
        self.assertEqual(self.calls(case(ratio=bits(-1e-16), balances=(0, 0)), "apply")[0][2], 0)

    def test_negative_ratio_below_the_tiny_bound_is_empty(self):
        self.assertEqual(self.outcome(case(ratio=bits(-0.25), balances=(0, 0)))[0], ("none",))

    def test_nan_ratio_is_empty_and_inf_ratio_casts_to_zero(self):
        self.assertEqual(self.outcome(case(ratio=bits(float("nan"))))[0], ("none",))
        outcome, log, _ = self.outcome(case(ratio=bits(float("inf")), items={KEYS[3]: (bits(float("inf")), 5000, 4000)}))
        self.assertEqual(outcome[0], "none")

    def test_ratio_above_the_entry_value_is_empty(self):
        self.assertEqual(self.outcome(case(items={KEYS[3]: (bits(0.1), 5000, 4000)}))[0], ("none",))

    def test_entry_value_below_tiny_is_empty(self):
        self.assertEqual(self.outcome(case(items={KEYS[3]: (bits(1e-16), 5000, 4000)}))[0], ("none",))

    def test_zero_vault_amount_is_empty_through_the_lane_guard(self):
        c = case(amounts={}, set_keys=[], set_count=0, balances=(-5, -5))
        self.assertEqual(self.outcome(c)[0], ("none",))

    def test_nan_rate_gives_no_leader(self):
        outcome, log, _ = self.outcome(case(rate=bits(float("nan"))))
        self.assertEqual(outcome[0], "ok")
        fields = dict(outcome[1])
        self.assertEqual(struct.unpack("<Q", fields[0xB0][8:])[0], vs.TAG_NONE)
        self.assertNotIn(0xC8, fields)
        self.assertEqual(len(self.calls(case(rate=bits(float("nan"))), "credit")), 1)

    def test_rate_above_one_pays_more_than_held_and_the_depositor_gets_nothing(self):
        c = case(rate=bits(2.0))
        credits = self.calls(c, "credit")
        self.assertEqual([entry[3] for entry in credits], [1998612, 0])
        self.assertGreater(self.outcome(c)[2][1][0][1], 4000)      # keep is negative, so slot3 grows

    def test_units_borrow_zeroes_the_entry_and_fires_the_units_site(self):
        c = case(effect="rewrite", rewrite=(2, 9))
        self.assertIn(0x44AFE13, self.events(c))
        self.assertEqual(self.outcome(c)[2][1][0][0], 0)

    def test_signed_negative_units_after_the_callee_are_a_large_unsigned_count(self):
        c = case(effect="rewrite", rewrite=(-5, 9))
        self.assertNotIn(0x44AFE13, self.events(c))

    def test_balance_is_read_for_the_vault_key_with_the_ledger_word(self):
        for entry in self.calls(case(), "balance"):
            self.assertEqual(entry[1], vs.LEDGER)
            self.assertEqual(entry[2], KEYS[0])

    def test_debit_precedes_apply_precedes_credits(self):
        order = [entry[0] for entry in self.outcome(case())[1] if entry[0] in ("debit", "apply", "credit")]
        self.assertEqual(order, ["debit", "apply", "credit", "credit"])

    def test_error_path_leaves_the_ledger_and_entries_alone(self):
        outcome, log, memory = self.outcome(case(balances=(1000000, 0)))
        self.assertEqual(outcome, ("error",))
        self.assertEqual(memory, (10 ** 9, ((5000, 4000),)))

    def test_limit_and_other_pass_through(self):
        self.assertEqual(self.calls(case(other=-123), "apply")[0][4], -123)
        fields = dict(self.outcome(case(limit=2000000000))[0][1])
        self.assertEqual(struct.unpack("<dd", fields[8])[0], 2000.0)

    def test_result_untouched_bytes_keep_the_fill(self):
        self.outcome(case())     # the harness raises Halt for any write outside the documented fields
        self.assertEqual(vs.run_case(self.harness, case())[0][0], "ok")

    def test_context_words_reach_every_amount_call(self):
        for entry in self.calls(case(ctx=(vs.LEDGER, 77, 88)), "amount"):
            self.assertEqual(entry[1], (vs.LEDGER, 77, 88))


class TestEventSitesReached(Fixture):
    """A crafted case for every event site that can fire; the expected address is the call site of the Qty operation."""

    def sites_of(self, c):
        return [entry[1] for entry in self.outcome(c)[1] if entry[0] == "event"]

    def test_cut_site(self):
        c = case(amounts={KEYS[0]: vs.MAX64}, set_keys=[], set_count=0, ratio=bits(-1.0))
        self.assertIn(0x44B0118, self.sites_of(c))

    def test_diff_sites(self):
        self.assertEqual(self.sites_of(case(balances=(vs.MIN64, vs.MIN64)))[:2], [0x44B0189, 0x44B01C2])

    def test_debit_site(self):
        self.assertIn(0x44B02CD, self.sites_of(case(counter=vs.MIN64 + 5)))

    def test_slot3_site(self):
        c = case(items={KEYS[3]: (bits(0.9), 5000, vs.MIN64)})
        self.assertIn(0x44B03A2, self.sites_of(c))

    def test_gap_sites(self):
        sites = self.sites_of(case(limit=vs.MIN64))
        self.assertIn(0x44B03EB, sites)
        self.assertIn(0x44B0434, sites)

    def test_leader_credit_site(self):
        self.assertIn(0x44B0468, self.sites_of(case(rate=bits(2.0), counter=vs.MAX64)))

    def test_units_site(self):
        self.assertIn(0x44AFE13, self.sites_of(case(effect="rewrite", rewrite=(1, 0))))

    def test_after_site(self):
        c = case(amounts={KEYS[0]: vs.MIN64}, set_keys=[], set_count=0, ratio=bits(1.5), items={KEYS[3]: (bits(2.0), 5000, 4000)},
                 balances=(1 << 62, 1 << 62))
        self.assertIn(0x44B0307, self.sites_of(c))

    def test_dead_sites_never_fire_on_extreme_inputs(self):
        extremes = (vs.MAX64, vs.MIN64, 0, 1, -1, 1 << 62)
        for amount in extremes:
            for ratio in (0.0, 0.5, 1.0, 1.5, -1.0, 1e300):
                for balance in (0, 1000, vs.MAX64, vs.MIN64, -5):
                    for counter in (0, vs.MAX64, vs.MIN64):
                        c = case(amounts={KEYS[0]: amount}, set_keys=[], set_count=0, ratio=bits(ratio), balances=(balance, balance), counter=counter,
                                 items={KEYS[3]: (bits(2.0), 5000, 4000)})
                        sites = self.sites_of(c)
                        self.assertNotIn(0x44B0153, sites)
                        self.assertNotIn(0x44B0369, sites)

    def test_lazy_flag_changes_only_the_log(self):
        plain, with_lazy = self.outcome(case()), self.outcome(case(lazy=1))
        self.assertEqual(plain[0], with_lazy[0])
        self.assertEqual(plain[2], with_lazy[2])
        self.assertEqual(len(with_lazy[1]), len(plain[1]) + 2)

    def test_ring_and_tree_agree_on_many_random_cases(self):
        for index, c in enumerate(vs.random_cases(60, seed=77)):
            ring = vs.run_case(self.harness, vs.Case(**{slot: getattr(c, slot) for slot in vs.Case.__slots__ if slot != "store"}, store="ring"))
            tree = vs.run_case(self.harness, vs.Case(**{slot: getattr(c, slot) for slot in vs.Case.__slots__ if slot != "store"}, store="tree"))
            self.assertEqual(ring[0], tree[0], index)
            self.assertEqual(ring[1], tree[1], index)


class TestShapes(Fixture):
    """Every container size and rotation the body can meet, against the rule list."""

    def test_every_deque_rotation_and_size(self):
        runs = 0
        for size in range(0, 8):
            items = {KEYS[i]: (bits(0.9), 100 + i, i) for i in range(2, 2 + size)}
            for spare in (0, 1, 3):
                cap = max(1, size + spare)
                for head in range(cap):
                    for key in (KEYS[0], KEYS[2], KEYS[2 + max(size - 1, 0)], KEYS[13]):
                        self.outcome(case(items=items, cap=cap, head=head, key=key))
                        runs += 1
        self.assertGreater(runs, 300)

    def test_every_tree_size(self):
        runs = 0
        for size in range(0, 14):
            items = {KEYS[i]: (bits(0.9), 100 + i, i) for i in range(size)}
            plans = [(0, [])] if size < 12 else [(1, []), (1, [2])]
            if size >= 5:
                plans += [(1, []), (1, [2]), (1, [4])]
            if size >= 12:
                plans += [(2, [])]
            for height, chunks in plans:
                for key in (KEYS[0], KEYS[size // 2], KEYS[size - 1] if size else KEYS[0], KEYS[13]):
                    self.outcome(case(items=items, store="tree", height=height, chunks=chunks, key=key))
                    runs += 1
        self.assertGreater(runs, 100)

    def test_every_set_size_and_count(self):
        runs = 0
        for size in range(0, 14):
            members = KEYS[1:1 + size]
            plans = [(0, [])] if size < 12 else [(1, [])]
            if size >= 5:
                plans += [(1, []), (1, [2]), (1, [4])]
            if size >= 12:
                plans += [(2, [])]
            for height, chunks in plans:
                for count in sorted({0, 1, size // 2, size, size + 1}):
                    self.outcome(case(set_keys=members, set_count=count, set_height=height, set_chunks=chunks))
                    runs += 1
        self.assertGreater(runs, 80)

    def test_fill_bytes_do_not_change_the_result(self):
        outcomes = set()
        for fill in (0x00, 0x5A, 0xC3, 0xFF):
            items = {KEYS[i]: (bits(0.9), 100 + i, i) for i in range(1, 8)}
            got = vs.run_case(self.harness, case(items=items, store="tree", height=1, fill=fill, key=KEYS[4]))
            outcomes.add(repr(got))
            self.assertEqual(got, vs.spec(case(items=items, store="tree", height=1, fill=fill, key=KEYS[4])))
        self.assertEqual(len(outcomes), 1)


class TestStub(Fixture):
    def test_stub_checks_refuse_a_wrong_lazy_argument(self):
        broken = vs.Harness(self.image)
        broken.machine.memory.statics[vs.LAZY_WORD] = 1
        self.assertEqual(vs.run_case(broken, case(lazy=1)), vs.spec(case(lazy=1)))
        original = broken.on_lazy
        broken.machine.slots[vs.MARK_BASE + vs.SLOT_LAZY] = lambda machine: machine.regs.__setitem__(vs.RSI, 0) or original(machine)
        self.assertEqual(vs.run_case(broken, case(lazy=1))[0][0], "halt")

    def test_unmodelled_callee_halts(self):
        stripped = vs.Harness(self.image)
        del stripped.machine.calls[vs.CREDIT]
        self.assertEqual(vs.run_case(stripped, case())[0][0], "halt")

    def test_search_must_run_as_real_code(self):
        plain = vs.Harness(self.image)
        plain.machine.real = frozenset()
        self.assertEqual(vs.run_case(plain, case())[0][0], "halt")

    def test_memory_outside_the_image_halts(self):
        trapped = vs.Harness(self.image, {vs.ENTRY: 0xCC})
        self.assertEqual(vs.run_case(trapped, case())[0][0], "halt")


class TestRandomStream(Fixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cases = vs.named_cases() + list(vs.random_cases(900, seed=0xBEEF))
        cls.hits = set()
        cls.stats, cls.caught, cls.rows = vs.check_stream(cls.harness, cls.cases, vs.VARIANTS, keep=100, hits=cls.hits)

    def test_no_mismatch(self):
        self.assertEqual(self.stats["mismatches"], 0, self.stats["first_mismatch"])
        self.assertEqual(self.stats["cases"], len(self.cases))

    def test_every_outcome_kind_is_exercised(self):
        kinds = set(self.stats["kinds"])
        for wanted in ("ok", "none", "error", "panic:0x44b01a5", "panic:0x44b04ae", "panic:0x44b04a1"):
            self.assertIn(wanted, kinds)

    def test_both_stores_are_exercised(self):
        self.assertGreater(self.stats["stores"]["ring"], 100)
        self.assertGreater(self.stats["stores"]["tree"], 100)

    def test_every_wrong_reading_is_refused(self):
        for name in vs.VARIANTS:
            self.assertGreater(self.caught[name][0], 0, name)

    def test_many_instructions_are_reached(self):
        self.assertGreater(len(self.hits), 800)

    def test_event_sites_are_reached(self):
        seen = {entry[1] for case_ in self.cases[:200] for entry in vs.spec(case_)[1] if entry[0] == "event"}
        self.assertGreaterEqual(len(seen), 8)

    def test_a_tampered_event_location_is_refused(self):
        wide = case(amounts={KEYS[0]: vs.MAX64, KEYS[1]: 5, KEYS[5]: 5})
        saved = dict(vs.LOCATION)
        vs.LOCATION["acc"] ^= 8
        try:
            self.assertNotEqual(vs.run_case(self.harness, wide), vs.spec(wide))
        finally:
            vs.LOCATION.update(saved)


class TestControls(Fixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cases = vs.named_cases()
        hits = set()
        vs.check_stream(cls.harness, cls.cases + list(vs.random_cases(300)), (), hits=hits)
        cls.mutants = vs.mutants_of(cls.image, hits)

    def test_structural_controls_all_detected(self):
        rows = vs.structural_controls(self.image, self.harness, self.cases)
        self.assertGreaterEqual(len(rows), 10)
        for name, detected, how in rows:
            self.assertTrue(detected, name)

    def test_mutants_cover_all_three_kinds(self):
        self.assertEqual({row[1] for row in self.mutants}, {"condition", "immediate", "displacement"})
        self.assertGreater(len(self.mutants), 250)

    def test_sampled_mutants_are_refused(self):
        cases = self.cases + list(vs.random_cases(200))
        sample = self.mutants[::40]
        rows = vs.run_mutants(self.image, sample, cases)
        self.assertTrue(rows)
        for row in rows:
            self.assertTrue(row[5] or row[2] in vs.EQUIVALENT, row)

    def test_condition_edits_flip_the_jcc_byte_only(self):
        for va, kind, at, old, new in self.mutants:
            if kind == "condition":
                self.assertEqual(old ^ new, 1)

    def test_equivalent_table_names_real_edit_addresses(self):
        addresses = {row[2] for row in self.mutants}
        for at in vs.EQUIVALENT:
            self.assertIn(at, addresses)
            self.assertGreater(len(vs.EQUIVALENT[at]), 30)


class TestRender(Fixture):
    def test_tsv_is_plain_text_with_header(self):
        name, text = vs.tsv("x.tsv", ("a", "b"), [(1, 2), (3, 4)])
        self.assertEqual((name, text), ("x.tsv", "a\tb\n1\t2\n3\t4\n"))

    def test_operand_text(self):
        self.assertEqual(vs.operand_text(("r", 3)), "rbx")
        self.assertEqual(vs.operand_text(("x", 2)), "xmm2")
        self.assertEqual(vs.operand_text(("m", 15, None, 1, 0xE6, False)), "[r15+230]")
        self.assertEqual(vs.operand_text(("m", None, None, 1, 0x64F01D8, False)), "[0x64f01d8]")
        self.assertEqual(vs.operand_text(("i", -1)), "0xffffffffffffffff")

    def test_blocks_partition_the_body(self):
        rows = vs.block_rows(self.image, {})
        body = [row for row in rows if int(row[0], 16) < vs.SEARCH]
        self.assertEqual(sum(row[2] for row in body), 954)
        self.assertEqual(int(body[0][0], 16), vs.ENTRY)

    def test_instruction_rows_have_bytes(self):
        rows = vs.instruction_rows(self.image, {})
        self.assertEqual(rows[0][0], "0x44af2f0")
        self.assertEqual(rows[0][2], "55")
        self.assertEqual(rows[0][3], "push")

    def test_callee_table_counts(self):
        rows = vs.callee_rows(self.image)
        kinds = {}
        for row in rows:
            kinds[row[1]] = kinds.get(row[1], 0) + 1
        self.assertEqual(kinds["direct"], 8)
        self.assertEqual(kinds["slot"], 24)
        self.assertEqual(kinds["register"], 2)

    def test_layout_rows_name_every_object(self):
        objects = {row[0] for row in vs.layout_rows()}
        self.assertEqual(objects, {"state", "set node", "map node", "deque entry", "ledger", "result"})

    def test_measure_keys(self):
        files, measure, survivors = vs.render(self.small_result())
        self.assertEqual(json.loads(files["measure.json"]), measure)
        for key in ("cases", "negative_controls", "negative_detected", "equivalent"):
            self.assertIn(key, measure)

    def small_result(self):
        hits = set()
        stats, caught, rows = vs.check_stream(self.harness, vs.named_cases(), vs.VARIANTS, keep=1, hits=hits)
        mutants = vs.run_mutants(self.image, vs.mutants_of(self.image, hits)[:6], vs.named_cases())
        return {"image": self.image, "sites": self.sites, "stats": stats, "caught": caught, "rows": rows, "mutants": mutants,
                "controls": [("x", True, "y")], "hits": hits, "branches": dict(self.harness.machine.branches),
                "counts": dict(self.harness.machine.counts), "kill_cases": 1}


if __name__ == "__main__":
    unittest.main()
