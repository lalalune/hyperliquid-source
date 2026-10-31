import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import order_request_view as t  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-order-request-view-94"


def shared(cls):
    cls.image = t.load_image()
    cls.harness = t.Harness(cls.image)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared)

    def record(self, perp=False, world=None, **fields):
        case = t.WireCase("test", perp, t.request(**fields), **(world or {}))
        run = self.harness.run(case)
        self.assertIsNone(run["stop"])
        self.assertIsNone(t.compare_run(self.harness, case))
        return run["answer"]

    def stop(self, perp=False, world=None, **fields):
        case = t.WireCase("test", perp, t.request(**fields), **(world or {}))
        self.assertIsNone(t.compare_run(self.harness, case))
        return self.harness.run(case)["stop"]


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
            self.image.exact_fde(t.SPOT_REQUEST + 1)

    def test_address_outside_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "outside every FDE"):
            self.image.fde(0x10)

    def test_bss_never_resolves(self):
        section = self.image.named[".bss"]
        with self.assertRaisesRegex(t.EvidenceError, "outside file-backed"):
            self.image.offset(section["address"] + 8)

    def test_twins(self):
        row = t.twin_rows(self.image, t.SPOT_REQUEST, t.PERP_REQUEST)
        self.assertEqual(row["call_targets_that_differ"], {"%#x" % t.SPOT_RESTING: "%#x" % t.PERP_RESTING, "%#x" % t.SPOT_TRIGGER: "%#x" % t.PERP_TRIGGER, "%#x" % t.SPOT_ROWS: "%#x" % t.PERP_ROWS})
        row = t.twin_rows(self.image, t.SPOT_ROWS, t.PERP_ROWS)
        self.assertEqual(row["call_targets_that_differ"], {"%#x" % t.SPOT_REQUEST: "%#x" % t.PERP_REQUEST})

    def test_twins_negative_control(self):
        with self.assertRaisesRegex(t.EvidenceError, "twin length differs"):
            t.twin_rows(self.image, t.SPOT_REQUEST, t.SPOT_ROWS)


class Types(Base):
    def test_trigger_types(self):
        wanted = {(0, 0): "Take Profit Limit", (0, 1): "Take Profit Market", (1, 0): "Stop Limit", (1, 1): "Stop Market"}
        for (tpsl, market), name in wanted.items():
            self.assertEqual(self.record(tpsl=tpsl, market=market)["orderType"], name)

    def test_low_three_bits_pick_market(self):
        self.assertEqual(self.record(word=3)["orderType"], "Market")
        self.assertEqual(self.record(word=0xB)["orderType"], "Market")
        self.assertEqual(self.record(word=4)["orderType"], "Limit")

    def test_market_byte_is_ignored_with_no_trigger(self):
        self.assertEqual(self.record(market=1, word=2)["orderType"], "Limit")

    def test_tif_is_the_low_byte(self):
        self.assertEqual(self.record(word=0x1234)["tif"], 0x34)

    def test_trigger_tif_is_5(self):
        self.assertEqual(self.record(tpsl=0, word=0x1234)["tif"], 5)

    def test_trigger_price_is_the_word(self):
        record = self.record(True, tpsl=1, word=3000000000)
        self.assertEqual(t.to_float(record["triggerPx"]), 30000000.0)

    def test_buy_take_profit_below(self):
        self.assertTrue(self.record(tpsl=0, side=0)["triggerCondition"].startswith("Price below"))

    def test_buy_stop_above(self):
        self.assertTrue(self.record(tpsl=1, side=0)["triggerCondition"].startswith("Price above"))

    def test_sell_stop_below(self):
        self.assertTrue(self.record(tpsl=1, side=1)["triggerCondition"].startswith("Price below"))

    def test_no_size_is_whole_position(self):
        record = self.record(has=0, sz=77)
        self.assertEqual((record["isPositionTpsl"], record["sz"], record["origSz"]), (1, 0, 0))


class Time(Base):
    def test_epoch_is_zero(self):
        self.assertEqual(self.record(date=t.date_word(1970, 1), seconds=0, nanos=0)["timestamp"], 0)

    def test_first_millisecond(self):
        self.assertEqual(self.record(date=t.date_word(1970, 1), seconds=0, nanos=1000000)["timestamp"], 1)

    def test_below_a_millisecond_drops(self):
        self.assertEqual(self.record(date=t.date_word(1970, 1), seconds=0, nanos=999999)["timestamp"], 0)

    def test_leap_second_nanos(self):
        self.assertEqual(self.record(date=t.date_word(1970, 1), seconds=1, nanos=1999999999)["timestamp"], 2999)

    def test_before_1970_is_zero(self):
        self.assertEqual(self.record(date=t.date_word(1969, 365), seconds=86399, nanos=0)["timestamp"], 0)

    def test_known_day(self):
        self.assertEqual(self.record(date=t.date_word(2024, 60), seconds=3600, nanos=123456789)["timestamp"], 1709168400123)

    def test_spec_matches_python_calendar(self):
        for year, ordinal in ((2024, 366), (2001, 1), (2100, 60)):
            wanted = t.datetime.date(year, 1, 1).toordinal() + ordinal - 1 - t.WIRE_DAY_ZERO
            self.assertEqual(t.spec_millis(t.date_word(year, ordinal), 0, 0), wanted * 86400000)


class Kids(Base):
    def test_kid_takes_oid_and_time_of_the_parent(self):
        record = self.record(kids=(t.request(oid=9, seconds=7),), oid=0xABCDE, seconds=5)
        self.assertEqual(record["children"][0]["oid"], 0xABCDE)
        self.assertEqual(record["children"][0]["timestamp"], record["timestamp"])

    def test_kid_keeps_its_own_head(self):
        record = self.record(kids=(t.request(px=4242, tpsl=1, word=99),))
        kid = record["children"][0]
        self.assertEqual((kid["isTrigger"], kid["orderType"]), (1, "Stop Limit"))

    def test_room_is_freed_by_capacity(self):
        run = self.harness.run(t.WireCase("test", False, t.request(room=4, kids=(t.request(),))))
        self.assertIn(("free", 4 * t.KID_STRIDE), run["events"])

    def test_room_and_no_kids(self):
        run = self.harness.run(t.WireCase("test", False, t.request(room=3)))
        self.assertIn(("free", 3 * t.KID_STRIDE), run["events"])

    def test_no_room_no_free(self):
        run = self.harness.run(t.WireCase("test", False, t.request()))
        self.assertEqual([row for row in run["events"] if row[0] == "free"], [])

    def test_wrong_kid_spec_is_seen(self):
        case = t.WireCase("test", False, t.request(kids=(t.request(),)))
        actual = self.harness.run(case)
        expected = t.spec_run(t.WireCase("test", False, t.request(kids=(t.request(px=5),))))
        self.assertNotEqual(actual["answer"], expected["answer"])


class Stops(Base):
    def test_spot_past_list(self):
        self.assertEqual(self.stop(world={"asset": 40, "list_len": 4}), ("bounds", 40, 4, t.LOC_LIST))

    def test_perp_other_dex(self):
        self.assertEqual(self.stop(True, world={"asset": 10001, "dex": 0}), ("panic", t.LOC_PERP))


class Mutants(Base):
    def mutant(self, va, offset, value, case):
        machine = self.harness.machine
        machine.patches = {va + offset: value}
        machine.cache.pop(va, None)
        try:
            return t.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)

    def test_two_byte_gate(self):
        case = t.WireCase("test", False, t.request())
        self.assertIsNotNone(self.mutant(0x42FEA71, 1, 3, case))

    def test_day_constant(self):
        case = t.WireCase("test", False, t.request())
        self.assertIsNotNone(self.mutant(0x42FEADF, 3, 0x81, case))

    def test_every_case_agrees(self):
        troubles = [row for row in (t.compare_run(self.harness, case) for case in t.all_cases()) if row]
        self.assertEqual(troubles, [])


class Packet(unittest.TestCase):
    def test_manifest(self):
        rows = [line.split("  ") for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines()]
        self.assertEqual(sorted(name for _, name in rows), sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"))
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

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
