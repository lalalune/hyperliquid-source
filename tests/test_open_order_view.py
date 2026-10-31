import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import open_order_view as t  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-open-order-view-94"


def shared(cls):
    cls.image = t.load_image()
    cls.harness = t.Harness(cls.image)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared)

    def run_case(self, case):
        return self.harness.run(case)

    def answer(self, case):
        run = self.run_case(case)
        self.assertIsNone(run["stop"])
        self.assertIsNone(t.compare_run(self.harness, case))
        return run["answer"]

    def stop(self, case):
        run = self.run_case(case)
        self.assertIsNone(t.compare_run(self.harness, case))
        return run["stop"]

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
    def test_digest(self):
        self.assertEqual(hashlib.sha256(t.BINARY.read_bytes()).hexdigest(), t.SHA256)

    def test_wrong_digest_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "SHA-256 mismatch"):
            t.load_image(expected="0" * 64)

    def test_changed_byte_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            data = bytearray(t.BINARY.read_bytes()[:4096])
            data[100] ^= 1
            path.write_bytes(bytes(data))
            with self.assertRaisesRegex(t.EvidenceError, "SHA-256 mismatch"):
                t.load_image(path=path)


class Static(Base):
    def test_exact_function_starts(self):
        for start, _ in t.GROUPS:
            self.assertEqual(self.image.exact_fde(start)[0], start)

    def test_inside_a_function_is_not_a_start(self):
        with self.assertRaisesRegex(t.EvidenceError, "not an FDE start"):
            self.image.exact_fde(t.SPOT_RESTING + 1)

    def test_address_outside_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "outside every FDE"):
            self.image.fde(0x10)

    def test_address_outside_file_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "outside file-backed"):
            self.image.offset(0x7FFFFFFFFF)

    def test_bss_never_resolves(self):
        section = self.image.named[".bss"]
        with self.assertRaisesRegex(t.EvidenceError, "outside file-backed"):
            self.image.offset(section["address"] + 8)

    def test_writer_names_every_field_in_order(self):
        rows = t.read_writer(self.image)
        self.assertEqual([row["name"] for row in rows], list(t.FIELD_OFFSETS))
        self.assertEqual({row["name"]: int(row["offset"], 16) for row in rows}, t.FIELD_OFFSETS)

    def test_writer_map_negative_control(self):
        saved = t.FIELD_OFFSETS["sz"]
        t.FIELD_OFFSETS["sz"] = 0x60
        try:
            with self.assertRaisesRegex(t.EvidenceError, "writer field map differs"):
                t.read_writer(self.image)
        finally:
            t.FIELD_OFFSETS["sz"] = saved

    def test_power_table(self):
        row = t.read_powers(self.image)
        self.assertEqual(row["rows"], 256)
        self.assertEqual(row["first_row_not_nearest"], 25)

    def test_power_table_negative_control(self):
        with tempfile.TemporaryDirectory():
            blob = bytearray(self.image.blob)
            struct.pack_into("<d", blob, self.image.offset(t.POWERS_AT) + 8 * 7, 3.0)
            changed = type(self.image).__new__(type(self.image))
            changed.__dict__.update(self.image.__dict__)
            changed.blob = bytes(blob)
            with self.assertRaisesRegex(t.EvidenceError, "power table shape"):
                t.read_powers(changed)

    def test_constants(self):
        self.assertEqual(t.read_constants(self.image)["order_table_rows"], 10)

    def test_constants_negative_control(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(t.ABOVE_AT)] ^= 1
        changed = type(self.image).__new__(type(self.image))
        changed.__dict__.update(self.image.__dict__)
        changed.blob = bytes(blob)
        with self.assertRaisesRegex(t.EvidenceError, "constant bytes: above"):
            t.read_constants(changed)

    def test_twins_differ_only_in_targets(self):
        rows = t.twin_rows(self.image, t.SPOT_LOOKUP, t.PERP_LOOKUP)
        self.assertEqual(rows["call_targets_that_differ"], {"%#x" % t.SPOT_TRIGGER: "%#x" % t.PERP_TRIGGER, "%#x" % t.SPOT_RESTING: "%#x" % t.PERP_RESTING})
        rows = t.twin_rows(self.image, t.SPOT_CHILDREN, t.PERP_CHILDREN)
        self.assertEqual(rows["call_targets_that_differ"], {"%#x" % t.SPOT_LOOKUP: "%#x" % t.PERP_LOOKUP})

    def test_twins_negative_control(self):
        with self.assertRaisesRegex(t.EvidenceError, "twin length differs"):
            t.twin_rows(self.image, t.SPOT_LOOKUP, t.SPOT_CHILDREN)

    def test_slots(self):
        for slot, value in ((t.SLOT_ORDER_TEXT, t.ORDER_TEXT), (t.SLOT_OUTCOME_ID, t.OUTCOME_ID), (t.SLOT_FLOAT_FMT, t.FLOAT_WRAP)):
            self.assertEqual(self.harness.relative[slot], value)

    def test_panic_locations(self):
        for slot in t.LOCATION_NAMES:
            path, line, _ = self.image.location(slot, self.harness.relative)
            self.assertTrue(path.endswith(".rs"), path)
            self.assertGreater(line, 0)


class Coins(Base):
    def coin(self, *arguments, **fields):
        return self.answer(t.resting_case("coin", False, *arguments, **fields))["coin"]

    def test_first_spot_is_purr(self):
        self.assertEqual(self.coin(asset=0), "PURR/USDC")

    def test_index_name(self):
        self.assertEqual(self.coin(asset=107, list_len=108), "\x40107")

    def test_last_at_name(self):
        self.assertEqual(self.coin(asset=99999999, list_len=100000000), "\x4099999999")

    def test_hash_name_from_the_index(self):
        self.assertEqual(self.coin(asset=100000007, list_len=100000008), "#7")

    def test_outcome_first_token(self):
        self.assertEqual(self.coin(spot=(7, 0), tokens={0: (0, 6), 7: (2, 2)}, row_count=8), "#30")

    def test_outcome_second_token(self):
        self.assertEqual(self.coin(spot=(9, 0), tokens={0: (0, 6), 9: (2, 2)}, row_count=10), "#31")

    def test_outcome_beats_index_zero(self):
        self.assertEqual(self.coin(spot=(4, 0), asset=0, map_b={4: 3}, map_c={3: (4, 9)}), "#30")

    def test_outcome_number_saturates(self):
        name = self.coin(spot=(4, 0), map_b={4: 2 ** 63}, map_c={2 ** 63: (2, 4)})
        self.assertEqual(name, "#%d" % (2 ** 64 - 1 - 100000000))

    def test_empty_second_map_is_a_plain_spot(self):
        self.assertEqual(self.coin(spot=(4, 0), map_b={4: 3}, map_c={3: (4, 9)}, empty_c=True), "\x401")

    def test_perp_coin_is_the_row_name(self):
        self.assertEqual(self.answer(t.resting_case("coin", True, asset=4))["coin"], "LONGNAME-ROW")

    def test_empty_perp_name(self):
        self.assertEqual(self.answer(t.resting_case("coin", True, asset=3))["coin"], "")


class Scales(Base):
    def test_spot_price_scale(self):
        record = self.answer(t.resting_case("scale", False, {"px": 12345678}))
        self.assertEqual(t.to_float(record["limitPx"]), 12345678 / 1e4)

    def test_spot_size_scale(self):
        record = self.answer(t.resting_case("scale", False, {"sz": 1500, "orig": 2000}))
        self.assertEqual(t.to_float(record["sz"]), 0.15)
        self.assertEqual(t.to_float(record["origSz"]), 0.2)

    def test_perp_price_scale(self):
        record = self.answer(t.resting_case("scale", True, {"px": 2500000000}, asset=1))
        self.assertEqual(t.to_float(record["limitPx"]), 2500000000 / 100.0)

    def test_perp_size_scale(self):
        record = self.answer(t.resting_case("scale", True, {"sz": 15000}, asset=1))
        self.assertEqual(t.to_float(record["sz"]), 1.5)

    def test_wei_below_size_panics(self):
        self.assertEqual(self.stop(t.resting_case("scale", False, tokens={0: (9, 1), 1: (2, 9)}, row_count=2)), ("overflow", t.LOC_WEI))

    def test_size_decimals_7_panic(self):
        self.assertEqual(self.stop(t.resting_case("scale", True, perps=[("BTC", 7), ("ETH", 7)], perp_len=2)), ("overflow", t.LOC_DECIMALS))

    def test_size_decimals_6(self):
        self.assertIsNotNone(self.answer(t.resting_case("scale", True, perps=[("BTC", 6), ("ETH", 6)], perp_len=2)))

    def test_table_row_25_is_read_not_computed(self):
        record = self.answer(t.resting_case("scale", False, {"px": 1}, tokens={0: (9, 25), 1: (0, 9)}, row_count=2))
        self.assertNotEqual(t.to_float(record["limitPx"]), 1 / 1e25)
        self.assertEqual(t.to_float(record["limitPx"]), 1 / t.POWERS[25])

    def test_other_dex_panics(self):
        self.assertEqual(self.stop(t.resting_case("scale", True, asset=10001, dex=0)), ("panic", t.LOC_PERP))

    def test_spot_past_list(self):
        self.assertEqual(self.stop(t.resting_case("scale", False, asset=40, list_len=4)), ("bounds", 40, 4, t.LOC_LIST))


class Text(Base):
    def test_every_order_type(self):
        for index, name in enumerate(t.ORDER_TYPES):
            self.assertEqual(self.harness.run(t.Case("text", kind="order_text", oid=index))["answer"], name)

    def test_resting_condition_splits_at_2(self):
        for kind in range(10):
            record = self.answer(t.resting_case("text", False, {"kind": kind}))
            self.assertEqual(record["triggerCondition"], "N/A" if kind < 2 else "Triggered")

    def test_buy_take_profit_is_below(self):
        record = self.answer(t.trigger_case("text", True, {"side": 0, "flag": 0, "trigger": 3000000000}, asset=1))
        self.assertEqual(record["triggerCondition"], "Price below 30000000")

    def test_buy_stop_is_above(self):
        record = self.answer(t.trigger_case("text", True, {"side": 0, "flag": 1, "trigger": 3000000000}, asset=1))
        self.assertTrue(record["triggerCondition"].startswith("Price above"))

    def test_trigger_fixed_fields(self):
        record = self.answer(t.trigger_case("text", True, {"has": 0, "sz": 99}))
        self.assertEqual((record["isTrigger"], record["isPositionTpsl"], record["tif"], record["sz"], record["origSz"]), (1, 1, 5, 0, 0))

    def test_trigger_with_size(self):
        record = self.answer(t.trigger_case("text", True, {"has": 1, "sz": 99}))
        self.assertEqual(record["isPositionTpsl"], 0)
        self.assertEqual(record["sz"], record["origSz"])
        self.assertNotEqual(record["sz"], 0)

    def test_float_text(self):
        self.assertEqual(t.float_text(30000000.0), "30000000")
        self.assertEqual(t.float_text(0.25), "0.25")
        self.assertEqual(t.float_text(1e21), "1000000000000000000000")


class Lookup(Base):
    def test_trigger_wins(self):
        world = t.World(False, triggers={t.USER_A: {t.TOP_OID: t.trigger_order()}}, resting={t.TOP_OID: (2, t.resting_order())})
        self.assertEqual(self.answer(t.Case("lookup", world=world))["isTrigger"], 1)

    def test_free_slot_is_none(self):
        world = t.World(False, resting={t.TOP_OID: (2, t.resting_order(tag=2))})
        run = self.run_case(t.Case("lookup", world=world))
        self.assertIsNone(run["answer"])
        self.assertEqual(self.harness.machine.memory.read(t.OUT, 8), t.NONE_WORD)

    def test_slab_end_is_none(self):
        world = t.World(False, slab_len=8, resting={t.TOP_OID: (8, t.resting_order())})
        self.assertIsNone(self.run_case(t.Case("lookup", world=world))["answer"])

    def test_item_count_zero_is_none(self):
        world = t.World(True, empty_book=True, resting={t.TOP_OID: (2, t.resting_order())})
        self.assertIsNone(self.run_case(t.Case("lookup", world=world))["answer"])

    def test_every_case_agrees(self):
        troubles = [row for row in (t.compare_run(self.harness, case) for case in t.all_cases()) if row]
        self.assertEqual(troubles, [])


class Children(Base):
    def test_order_and_growth(self):
        ids = tuple(range(0x100, 0x105))
        resting = {oid: (index + 3, t.resting_order(oid=oid)) for index, oid in enumerate(ids)}
        case = t.resting_case("kids", False, {"children": ids}, extra=resting, slab_len=16)
        record = self.answer(case)
        self.assertEqual([row["oid"] for row in record["children"]], list(ids))
        self.assertIn(("grow", 4), self.run_case(case)["events"])

    def test_missing_children_skipped(self):
        ids = (0x200, 0x201, 0x202)
        record = self.answer(t.resting_case("kids", False, {"children": ids}, extra={0x201: (1, t.resting_order(oid=0x201))}))
        self.assertEqual([row["oid"] for row in record["children"]], [0x201])

    def test_stored_user_reads_the_child(self):
        world = t.World(False, resting={t.TOP_OID: (2, t.resting_order(user=t.USER_B, children=(0x500,)))}, triggers={t.USER_B: {0x500: t.trigger_order(side=1)}, t.USER_A: {0x500: t.trigger_order(side=0)}})
        self.assertEqual(self.answer(t.Case("kids", world=world))["children"][0]["side"], 1)


class Mutants(Base):
    def test_table_scale_mutant(self):
        case = t.resting_case("mutant", True, asset=1)
        self.assertIsNone(t.compare_run(self.harness, case))
        self.assertIsNotNone(self.mutant(0x42FC43B, 1, 7, case))

    def test_wrong_stride_mutant(self):
        world = t.World(False, slab_len=8, resting={t.TOP_OID: (3, t.resting_order())})
        self.assertIsNotNone(self.mutant(0x4339150, 3, 0xF0, t.Case("mutant", world=world)))

    def test_order_text_mutant(self):
        self.assertIsNotNone(self.mutant(0x327B8A7, 2, 6, t.Case("mutant", kind="order_text", oid=0)))

    def test_harness_catches_a_wrong_spec(self):
        case = t.resting_case("spec", True, asset=1)
        saved = t.ORDER_TYPES
        t.ORDER_TYPES = ("Other",) + t.ORDER_TYPES[1:]
        try:
            self.assertIsNotNone(t.compare_run(self.harness, case))
        finally:
            t.ORDER_TYPES = saved


class Packet(unittest.TestCase):
    setUpClass = classmethod(lambda cls: None)

    def test_manifest(self):
        rows = [line.split("  ") for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines()]
        self.assertEqual(sorted(name for _, name in rows), sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"))
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_manifest_negative_control(self):
        rows = [line.split("  ") for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines()]
        self.assertNotEqual(hashlib.sha256((FOLDER / rows[0][1]).read_bytes() + b"x").hexdigest(), rows[0][0])

    def test_evidence_counts(self):
        document = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(document["mismatches"], 0)
        self.assertEqual(document["target"]["sha256"], t.SHA256)
        self.assertEqual(document["cases"]["total"], len(t.all_cases()))

    def test_mutation_rows_have_reasons(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertEqual(sum(1 for row in rows if row[3] != "killed" and not row[5]), 0)

    def test_every_row_counted(self):
        document = json.loads((FOLDER / "evidence.json").read_text())
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(sum(document["mutations"].values()), len(rows))


if __name__ == "__main__":
    unittest.main()
