import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import spot_sell_preprocess as t  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-spot-sell-preprocess-94"


def shared(cls):
    cls.image = t.load_image()
    cls.harness = t.Harness(cls.image)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared)

    def pre(self, which="a", **change):
        case = t.Case("test", "pre", which, t.pre_world(**change))
        self.assertEqual(t.compare_run(self.harness, case), "")
        return self.harness.run(case)

    def adapter(self, which="a", pre=None, **change):
        case = t.Case("test", "adapter", which, t.adapter_world(pre, **change))
        self.assertEqual(t.compare_run(self.harness, case), "")
        return self.harness.run(case)

    def result(self, which="a", **change):
        found = self.pre(which, **change)
        return t.word(found["out"], 0), found["out"]

    def assert_direct(self, flag=0, **change):
        tag, out = self.result(**change)
        self.assertEqual((tag, out[8]), (t.TAG_DIRECT, flag))

    def mutant(self, va, offset, value, case):
        """One patched byte: the run must stop agreeing with the specification."""
        machine = self.harness.machine
        machine.patches = {va + offset: value}
        machine.cache.pop(va, None)
        try:
            return t.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)


class Identity(Base):
    def test_wrong_digest_is_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "SHA-256 mismatch"):
            t.load_image(expected="0" * 64)

    def test_function_ends_come_from_fdes(self):
        self.assertEqual(self.image.exact_fde(t.PRE_A), (0x4C21720, 0x4C21C0C))
        self.assertEqual(self.image.exact_fde(t.PRE_B), (0x4C21230, 0x4C2171C))
        self.assertEqual(self.image.exact_fde(t.PRE_C), (0x26D2070, 0x26D2556))
        self.assertEqual(self.image.exact_fde(t.HEALTH_CLASS), (0x48CFB30, 0x48CFB89))
        self.assertEqual(self.image.exact_fde(t.HEALTH_CLASS_C), (0x28DB4E0, 0x28DB539))

    def test_a_middle_address_is_not_a_function_start(self):
        with self.assertRaisesRegex(t.EvidenceError, "not an FDE start"):
            self.image.exact_fde(t.PRE_A + 1)

    def test_address_past_every_section_is_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "outside file-backed"):
            self.image.offset(0x7FFFFFFFFFFF)

    def test_bss_has_no_file_bytes(self):
        bss = self.image.named[".bss"]
        with self.assertRaisesRegex(t.EvidenceError, "outside file-backed"):
            self.image.offset(bss["address"] + 8)


class Gates(Base):
    def test_accepted_order_is_rewritten(self):
        tag, out = self.result()
        self.assertEqual(tag, t.TAG_REPLACE)
        self.assertEqual(t.word(out, 8), 701)
        self.assertEqual((out[0x19], out[0x30], out[0x31]), (2, 1, 0))
        self.assertEqual((t.word(out, 0x48), t.word(out, 0x50), t.word(out, 0x58)), (t.BASE, t.QUOTE, 900))

    def test_guard_must_be_exactly_one(self):
        for value in (0, 2, 3, 0xFF):
            self.assert_direct(enabled=value)

    def test_paused_and_halted_read_bit_zero(self):
        self.assert_direct(paused=3)
        self.assert_direct(halted=1)
        self.assertEqual(self.result(paused=2)[0], t.TAG_REPLACE)
        self.assertEqual(self.result(halted=0xFE)[0], t.TAG_REPLACE)

    def test_spot_bound_panics_before_the_size_test(self):
        found = self.pre(order={"spot": 3, "tag": 0})
        self.assertEqual(found["stop"], ("bounds", 3, 3, t.LOC_SPOT))

    def test_spot_bound_does_not_run_on_a_closed_guard(self):
        self.assert_direct(enabled=0, order={"spot": 9})

    def test_order_shape(self):
        self.assert_direct(order={"tag": 0})
        self.assert_direct(order={"side": 0})
        self.assert_direct(order={"reduce": 1})
        self.assert_direct(order={"k": 1})
        self.assertEqual(self.result(order={"side": 2})[0], t.TAG_REPLACE)

    def test_both_tokens_need_a_map_row(self):
        self.assert_direct(tree=None)
        self.assert_direct(tree=((0x05, t.QUOTE, 0x90), ()))
        self.assert_direct(tree=((0x05, t.BASE, 0x90), ()))
        self.assertEqual(self.pre(tree=((0x05, t.QUOTE, 0x90), ()))["events"], [])

    def test_a_spare_key_slot_is_not_a_row(self):
        self.assert_direct(tree=((0x05,), ()), fill=t.BASE)

    def test_mode_gate(self):
        for mode in range(4):
            self.assert_direct(mode=mode)
        self.assertEqual(self.result(mode=4)[0], t.TAG_REPLACE)
        self.assertEqual(self.result(mode=5)[0], t.TAG_REPLACE)

    def test_report_error_keeps_its_code(self):
        tag, out = self.result(report=(1, 0x2B))
        self.assertEqual((tag, out[8]), (t.TAG_ERROR, 0x2B))

    def test_health_edges(self):
        self.assert_direct(report=(0, 101, 10, 100, 200))
        self.assertEqual(self.result(report=(0, 100, 10, 100, 200))[0], t.TAG_REPLACE)

    def test_room_error_keeps_its_code(self):
        tag, out = self.result(room=(1, 0x37))
        self.assertEqual((tag, out[8]), (t.TAG_ERROR, 0x37))

    def test_half_is_strict(self):
        self.assertEqual(self.result(balance=(329, 0, 7), room=(0, 170), amount=(1, 1000))[0], t.TAG_REPLACE)
        self.assert_direct(balance=(330, 0, 7), room=(0, 170), amount=(1, 1000))
        self.assert_direct(balance=(330, 0, 7), room=(0, 170), amount=(1, 1001))

    def test_borrowed_balance_records_and_floors(self):
        found = self.pre(balance=(100, 200, 7))
        self.assertIn(("recorded", t.LOC_RECORD), found["events"])
        self.assertEqual(t.word(found["out"], 0), t.TAG_REPLACE)

    def test_sum_saturates_and_records(self):
        found = self.pre(room=(0, t.U64))
        self.assertEqual(found["events"].count(("recorded", t.LOC_RECORD)), 1)
        self.assertEqual(found["out"][8], 0)

    def test_amount_refusal(self):
        self.assert_direct(amount=(0, 1000000))
        self.assert_direct(amount=(2, 1000000))

    def test_quote_tags(self):
        tag, out = self.result(quote=(3, 0x41, 1, 2, 900))
        self.assertEqual((tag, out[8]), (t.TAG_ERROR, 0x41))
        self.assert_direct(quote=(2, 700, 1900000, 2100000, 900))

    def test_room_not_x_is_compared_with_last(self):
        self.assert_direct(room=(0, 900), balance=(0, 0, 7))
        self.assertEqual(self.result(room=(0, 899), balance=(0, 0, 7))[0], t.TAG_REPLACE)
        self.assertEqual(self.result(quote=(1, 9000, 1900000, 2100000, 900))[0], t.TAG_REPLACE)

    def test_product_cap(self):
        band = (0, 0, 1, t.U64, 900)
        self.assertEqual(self.result(order={"size": 1, "price": t.PRODUCT_CAP}, quote=band)[0], t.TAG_REPLACE)
        self.assert_direct(order={"size": 1, "price": t.PRODUCT_CAP + 1}, quote=band)
        self.assert_direct(order={"size": 1 << 33, "price": (1 << 31) + 1}, quote=band)

    def test_notional_floor(self):
        self.assertEqual(self.result(notional=1000000000)[0], t.TAG_REPLACE)
        self.assert_direct(notional=999999999)

    def test_tif_mask_is_mod_32(self):
        for tif in (0, 2, 4, 0x20, 0x22):
            self.assert_direct(1, order={"tif": tif})
        for tif in (1, 3, 5, 6, 7, 0x21):
            self.assertEqual(self.result(order={"tif": tif})[0], t.TAG_REPLACE)

    def test_price_rises_to_low_and_stops_at_high(self):
        _, out = self.result(order={"price": 1000000})
        self.assertEqual(t.word(out, 0x20), 1900000)
        self.assert_direct(1, order={"price": 2100001})
        self.assert_direct(1, quote=(1, 700, 2100001, 2100000, 900), order={"price": 1000000})

    def test_size_rule(self):
        self.assertEqual(t.word(self.result(quote=(1, 5000, 1900000, 2100000, 9000))[1], 8), 1000)
        self.assertEqual(t.word(self.result(quote=(1, 999, 1900000, 2100000, 9000))[1], 8), 1000)
        self.assertEqual(t.word(self.result(quote=(1, 0, 1900000, 2100000, 9000))[1], 8), 1)
        self.assertEqual(t.word(self.result(quote=(0, 3, 1900000, 2100000, 900))[1], 8), 1000)

    def test_order_bytes_are_kept(self):
        _, out = self.result()
        order = t.make_order()
        self.assertEqual(out[0x10:0x19], order[0x10:0x19])
        self.assertEqual(out[0x1A:0x20], order[0x1A:0x20])
        self.assertEqual(out[0x32:0x43], order[0x32:0x43])
        self.assertEqual(out[0x43], t.STACK_MARK)


class Copies(Base):
    def test_all_cases_match(self):
        for case in t.all_cases():
            self.assertEqual(t.compare_run(self.harness, case), "")

    def test_first_two_differ_only_in_the_user_row(self):
        row = t.twin_rows(self.image, t.PRE_A, t.PRE_B)
        self.assertEqual(row["call_targets_that_differ"], {"0x46f2fe0": "0x46f2e60"})
        self.assertEqual((row["rip_targets_that_differ"], row["field_words_that_differ"]), ({}, {}))

    def test_third_copy_uses_its_own_callees(self):
        self.assertEqual(t.PRES["c"]["user_row"], 0x2755400)
        self.assertEqual(t.word(self.pre("c")["out"], 8), 701)

    def test_twin_check_refuses_a_changed_condition(self):
        other = copy.copy(self.image)
        blob = bytearray(self.image.blob)
        blob[self.image.offset(0x4C21248) + 1] ^= 1
        other.blob = bytes(blob)
        with self.assertRaisesRegex(t.EvidenceError, "twin condition"):
            t.twin_rows(other, t.PRE_A, t.PRE_B)

    def test_host_bytes_catch_a_changed_byte(self):
        other = copy.copy(self.image)
        blob = bytearray(self.image.blob)
        blob[self.image.offset(0x4C2190E) + 3] = 5
        other.blob = bytes(blob)
        with self.assertRaisesRegex(t.EvidenceError, "host bytes"):
            t.read_host_bytes(other)


class Callers(Base):
    def test_second_path(self):
        found = self.adapter()
        self.assertEqual(found["events"][1][0], "second")
        self.assertEqual(found["enabled"], 1)

    def test_failure_word_closes_the_guard(self):
        for which in sorted(t.COPIES):
            found = self.adapter(which, second=t.WORD_FAILED)
            self.assertEqual(found["enabled"], 0)
            self.assertEqual(t.word(found["out"], 0, 2), 0xE1)
            self.assertEqual(found["out"][2], 0xA)

    def test_error_code_is_dropped(self):
        found = self.adapter(pre=t.plain(3, 1))
        direct = [event for event in found["events"] if event[0] == "direct"][0]
        self.assertEqual(direct[-1], 0)

    def test_flag_goes_to_the_direct_path(self):
        direct = [event for event in self.adapter(pre=t.plain(2, 1))["events"] if event[0] == "direct"][0]
        self.assertEqual(direct[-1], 1)

    def test_context_above_one_skips_the_call(self):
        found = self.adapter(pre=t.plain(1, 9), context=t.context_with(2))
        self.assertNotIn("pre", [event[0] for event in found["events"]])

    def test_opposite_book(self):
        sell = [event for event in self.adapter(pre=t.plain(2, 0), order=t.make_order(side=1))["events"] if event[0] == "direct"][0]
        buy = [event for event in self.adapter(pre=t.plain(2, 0), order=t.make_order(side=0))["events"] if event[0] == "direct"][0]
        self.assertEqual((sell[3], buy[3]), (t.BASE, t.QUOTE))

    def test_direct_result_offset(self):
        self.assertEqual({key: value["skip"] for key, value in t.COPIES.items()}, {"a": 8, "b": 0, "c": 8, "d": 0})

    def test_cloid_flag_is_normalised(self):
        second = self.adapter(pre=t.replace_result(cloid=3))["events"][1]
        self.assertEqual(second[2][2][-1], 1)


class Health(Base):
    def run_row(self, row, which="a"):
        case = t.Case("test", "health", which, {"report": row})
        self.assertEqual(t.compare_run(self.harness, case), "")
        return self.harness.run(case)

    def test_classes(self):
        for row, wanted in (((0, 201, 10, 100, 200), 0), ((0, 200, 10, 100, 200), 1), ((0, 100, 10, 100, 200), 2), ((0, 10, 10, 100, 200), 3)):
            self.assertEqual(self.run_row(row)["class"], wanted)
            self.assertEqual(self.run_row(row, "c")["class"], wanted)

    def test_error_returns_the_code_in_the_class_word(self):
        found = self.run_row((1, 0x2B))
        self.assertEqual((found["flag"], found["class"]), (1, 0x2B))


class Controls(Base):
    def test_guard_compare(self):
        case = t.Case("c", "pre", "a", t.pre_world())
        self.assertIn("differs", self.mutant(0x4C21731, 6, 2, case))

    def test_mode_compare(self):
        case = t.Case("c", "pre", "a", t.pre_world(mode=4))
        self.assertTrue(self.mutant(0x4C2190E, 3, 5, case))

    def test_notional_floor_constant(self):
        case = t.Case("c", "pre", "a", t.pre_world(notional=999999999))
        self.assertTrue(self.mutant(0x4C21B07, 2, 0xFE, case))

    def test_spec_notices_a_changed_world(self):
        case = t.Case("c", "pre", "a", t.pre_world())
        found = self.harness.run(case)
        other = t.spec_run(t.Case("c", "pre", "a", t.pre_world(quote=(1, 701, 1900000, 2100000, 900))))
        self.assertNotEqual(found["out"], other["out"])

    def test_a_stub_argument_mismatch_is_seen(self):
        wanted = t.spec_run(t.Case("c", "pre", "a", t.pre_world()))
        found = self.harness.run(t.Case("c", "pre", "a", t.pre_world(order={"size": 1001})))
        self.assertNotEqual(found["events"], wanted["events"])

    def test_unmodelled_call_stops_the_run(self):
        self.harness.stubs({}, {})
        self.harness.real.stubs = frozenset()
        machine = self.harness.machine
        machine.real = frozenset()
        try:
            with self.assertRaisesRegex(t.Halt, "unmodelled"):
                self.harness.machine.memory.reset()
                self.harness.write_state(t.pre_world())
                self.harness.machine.memory.put_bytes(t.ORDER, t.make_order())
                self.harness.write_tree(t.TREE_FLAT, 1)
                self.harness.machine.memory.write(t.STATE + 0x568, 8, t.ROOT_NODE)
                self.harness.machine.memory.write(t.STATE + 0x570, 8, 0)
                machine.run(t.PRE_A, {t.RDI: t.OUT, t.RSI: t.ORDER, t.RDX: t.USER, t.RCX: t.STATE})
        finally:
            machine.real = self.harness.real


class Static(Base):
    def test_slots_and_names(self):
        relative = self.harness.relative
        self.assertEqual(relative[t.SLOT_QUOTE], 0x37344A0)
        rows = t.name_rows(self.image, relative)
        self.assertEqual(rows[-2], "portfolioMargin")
        self.assertEqual(rows[-1], "variant index 0 <= i < 5")

    def test_guard_writers(self):
        rows = t.guard_writers(self.image)
        self.assertEqual(len(rows), 21)
        self.assertEqual(sum(1 for row in rows if row[1] == "register"), 3)
        self.assertEqual({row[1] for row in rows}, {"register", "imm8 0x0"})

    def test_mutation_targets_include_every_group(self):
        starts = {row[0] for row in t.mutated_groups(self.image)}
        self.assertEqual(starts, {t.PRE_A, t.PRE_B, t.PRE_C, t.HEALTH_CLASS, t.HEALTH_CLASS_C})


class Packet(unittest.TestCase):
    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(line.split("  ")[1] for line in lines), names)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_evidence_counts(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), sum(doc["mutations"].values()))
        self.assertEqual(doc["mutations"]["unreached"], 0)
        for row in rows:
            fields = row.split("\t")
            if fields[3] != "killed":
                self.assertTrue(fields[5])
        self.assertEqual(len((FOLDER / "cases.tsv").read_text().splitlines()) - 1, doc["cases"]["total"])

    def test_tool_refuses_a_wrong_folder_argument(self):
        with tempfile.TemporaryDirectory() as folder:
            done = subprocess.run([sys.executable, str(ROOT / "tools" / "spot_sell_preprocess.py")], capture_output=True, text=True, cwd=folder)
            self.assertNotEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main()
