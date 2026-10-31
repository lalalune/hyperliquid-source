"""Checks for the spot fill fee settlement of node #94."""

import hashlib
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fees_spot_settlement as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "fees-spot-settlement-94"


class Base(unittest.TestCase):
    image = tool.load_image()
    harness = tool.Harness(image)
    cases = tool.all_cases()

    def pick(self, kind, label):
        return next(case for case in self.cases if case["kind"] == kind and case["label"] == label)

    def mutated(self, va, at, xor, case):
        machine = self.harness.machine
        base = self.image.offset(va)
        machine.patches = {va + at: self.image.blob[base + at] ^ xor}
        machine.cache.pop(va, None)
        try:
            return tool.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)

    def target(self, va, kind):
        begin, end = self.image.fde(va)
        return next(row for row in tool.mutation_targets(self.image, tool.decode_range(self.image, begin, end)) if row[0] == va and row[3] == kind)

    def killed(self, va, kind, case):
        _, at, xor, _ = self.target(va, kind)
        self.assertEqual(tool.compare_run(self.harness, case), "")
        self.assertTrue(self.mutated(va, at, xor, case))


class Inputs(Base):
    def test_digest_is_checked(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_the_file_fails(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x7FFFFFFFFFFF)

    def test_nobits_is_not_mapped(self):
        self.assertTrue(all(section["type"] != 8 for section in self.image.mapped))

    def test_function_bounds(self):
        sizes = {tool.FILL_FN: 0x1C0E, tool.CHARGE_FN: 0xDBB, tool.SPLIT_FN: 0x343}
        for start, size in sizes.items():
            self.assertEqual(self.image.exact_fde(start), (start, start + size))
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.SPLIT_FN + 1)

    def test_decoder_stops_on_the_end(self):
        with self.assertRaises(tool.EvidenceError):
            tool.decode_range(self.image, tool.SPLIT_FN, tool.SPLIT_FN + 2)

    def test_pins_refuse_other_bytes(self):
        saved = tool.PINS
        tool.PINS = (("0x26fe8c4", "00000000", "bad"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.pin_rows(self.image)
        finally:
            tool.PINS = saved

    def test_constants_refuse_another_value(self):
        saved = tool.FLOATS
        tool.FLOATS = ((0x20A528, 1.0, "bad"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.float_rows(self.image)
        finally:
            tool.FLOATS = saved

    def test_pool_is_the_sweep_tree(self):
        rows = {row[0]: row[1] for row in tool.pin_rows(self.image)}
        load = struct.unpack("<i", bytes.fromhex(rows["0x26fe8c4"])[3:])[0]
        base = struct.unpack("<i", bytes.fromhex(rows["0x26fe8d4"])[3:])[0]
        pool = struct.unpack("<i", bytes.fromhex(rows["0x372cb07"])[3:])[0]
        self.assertEqual(load - base, pool)

    def test_callers(self):
        rows = tool.caller_rows(self.image)
        forms = [(row[0], row[3]) for row in rows]
        self.assertIn(("0x26e9acc", "0x372b9d0"), forms)
        self.assertIn(("0x24fce08", "0x372e0a0"), forms)
        self.assertEqual(sorted(row[0] for row in rows if row[2] == "direct"), ["0x372c196", "0x372e392"])
        self.assertEqual(len(rows), 8)

    def test_locations_keep_no_build_root(self):
        for row in tool.location_rows(self.image):
            self.assertFalse(row[2].startswith(chr(0x2F)), row)
            self.assertTrue(row[3] > 0)


class Rules(Base):
    def test_share_arithmetic(self):
        self.assertEqual(tool.deployer_amount(1000, 50000, False), 500)
        self.assertEqual(tool.deployer_amount(1000, 50000, True), 0)
        self.assertEqual(tool.deployer_amount(100, 101000, False), 101)
        self.assertEqual(tool.deployer_amount(100, 101001, False), 0)
        self.assertEqual(tool.deployer_amount(tool.MAX, 101000, False), tool.MAX)

    def test_all_vectors_match(self):
        failed = [(case["label"], tool.compare_run(self.harness, case)) for case in self.cases]
        self.assertEqual([row for row in failed if row[1]], [])

    def fill(self, **over):
        case = tool.world(kind="fill", label="test", **over)
        self.assertEqual(tool.compare_run(self.harness, case), "")
        return self.harness.state_view()

    def test_worked_fill(self):
        got = self.fill(records=(tool.GROSS, tool.GROSS))
        balances = got["balances"]
        self.assertEqual(balances[(tool.BUYER, 3)][0], 77 + 496143)
        self.assertEqual(balances[(tool.BUYER, 2)][:2], (10 ** 12 - 350000000, 10 ** 10 - 350000000))
        self.assertEqual(balances[(tool.SELLER, 2)][0], 55 + 349991000)
        self.assertEqual(balances[(tool.SELLER, 3)][:2], (10 ** 12 - 500000, 10 ** 9 - 500000))
        self.assertEqual(got["pool"][3], 100000000 + 2315)
        self.assertEqual(got["pool"][2], 7000000 + 4500)
        self.assertEqual(balances[(tool.DEPLOY_A, 2)][0], 66 + 4500)
        self.assertEqual(balances[(tool.DEPLOY_B, 3)][0], 1542)
        self.assertEqual(got["created"], [tool.DEPLOY_B])

    def test_rebate_lands_on_the_paid_token(self):
        got = self.fill(records=(tool.REBATE, tool.NONE))
        self.assertEqual(got["balances"][(tool.BUYER, 2)][0], 10 ** 12 - 350000000 + 1500)
        self.assertEqual(got["pool"], {1: 500, 2: 7000000 - 1500, 3: 100000000})

    def test_gap_comes_from_the_pool(self):
        got = self.fill(records=(tool.fee_row(rebate=1500), tool.NONE), convert=(1, 1), pool={2: 5, 3: 100})
        self.assertEqual(got["pool"], {2: 0, 3: 100})
        got = self.fill(records=(tool.NONE, tool.fee_row(rebate=1500)), convert=(1, 1), pool={2: 5, 3: 100})
        self.assertEqual(got["pool"], {2: 5, 3: 0})
        self.assertIn((2, tool.LOC_SHORT_FILL), got["recorder"])
        self.assertIn((0, tool.LOC_FLOOR), got["recorder"])

    def test_no_fee_for_outcome_base(self):
        got = self.fill(records=(tool.PAID, tool.PAID), outcome=True)
        self.assertEqual(self.harness.seen, [])
        self.assertEqual(got["pool"], {1: 500, 2: 7000000, 3: 100000000})

    def test_charge_caps_at_available(self):
        case = tool.world(kind="charge", label="test", outcome=True, records=(tool.NONE, tool.GROSS), balances={(tool.SELLER, 2): (10000, 5000, 7)})
        self.assertEqual(tool.compare_run(self.harness, case), "")
        got = self.harness.state_view()
        self.assertEqual(got["balances"][(tool.SELLER, 2)], (5000, 5000, 7))
        self.assertEqual(got["pool"][2], 7000000 + 4500)
        self.assertEqual(got["balances"][(tool.DEPLOY_A, 2)][0], 4500)

    def test_hold_is_not_part_of_the_gate(self):
        want = tool.fill_spec(self.pick("fill", "balance hold above total 0"))
        self.assertEqual(want["result"], "settled")

    def test_panic_names_the_location(self):
        self.assertEqual(tool.fill_spec(self.pick("fill", "gross above receive")), {"panic": "none:%#x" % tool.LOC_RECEIVE})
        self.assertEqual(tool.compare_run(self.harness, self.pick("fill", "gross above receive")), "")
        self.assertEqual(tool.fill_spec(self.pick("fill", "one token self trade")), {"panic": "none:%#x" % tool.LOC_DEBIT})


class Controls(Base):
    def test_tail_sign(self):
        self.killed(0x372CB6E, "branch", self.pick("fill", "tail short pool small"))

    def test_token_row_flag(self):
        self.killed(0x372CC33, "branch", self.pick("fill", "fees gross/gross"))

    def test_cap_compare(self):
        self.killed(0x372CDF1, "branch", self.pick("fill", "share 200000"))

    def test_split_leg_slot(self):
        self.killed(0x3C018EC, "branch", self.pick("split", "grid 0 1 1 1 1 23"))

    def test_charge_cap(self):
        self.killed(0x372E488, "branch", self.pick("charge", "balance below"))

    def test_rebate_clear(self):
        self.killed(0x372E2FE, "branch", self.pick("charge", "fee both"))

    def test_wrong_expected_balance_is_seen(self):
        case = dict(self.pick("fill", "fees gross/gross"))
        want = tool.fill_spec(case)
        got = self.harness.run_fill(case)
        want["balances"][(tool.BUYER, 3)] = (1, 2, 3)
        self.assertEqual(tool.compare_state(self.harness, got, want), "balances differ")

    def test_crossed_record_is_seen(self):
        record = tool.record_image(tool.GROSS, 0)
        self.assertNotEqual(record, tool.record_image(tool.GROSS, 1))


class Packet(Base):
    evidence = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))

    def rows(self, name):
        return [line.split("\t") for line in (PACKET / name).read_text(encoding="utf-8").splitlines()[1:]]

    def test_cases_and_counts(self):
        self.assertEqual(self.evidence["cases"]["total"], len(self.cases))
        self.assertEqual(self.evidence["mismatches"], 0)
        self.assertEqual(self.evidence["target_sha256"], tool.SHA256)

    def test_mutation_rows_add_up(self):
        rows = self.rows("mutations.tsv")
        counts = {}
        for row in rows:
            counts[row[3]] = counts.get(row[3], 0) + 1
        self.assertEqual(counts, {key: value for key, value in self.evidence["mutations"].items() if value})
        for row in rows:
            if row[3] != "killed":
                self.assertTrue(row[5] and row[5] != tool.GROUP_REASONS, row)

    def test_function_hashes(self):
        for row in self.evidence["functions"]:
            start, end = int(row["start"], 16), int(row["end"], 16)
            base = self.image.offset(start)
            self.assertEqual(hashlib.sha256(bytes(self.image.blob[base:base + end - start])).hexdigest(), row["sha256"])

    def test_tables_regenerate(self):
        for name, rows in (("path-map.tsv", tool.path_rows()), ("split-rules.tsv", tool.split_rows()), ("call-sites.tsv", tool.caller_rows(self.image)), ("pins.tsv", tool.pin_rows(self.image)),
                           ("locations.tsv", tool.location_rows(self.image)), ("flows.tsv", tool.flow_rows(self.image)), ("reference-diff.tsv", tool.reference_rows())):
            self.assertEqual(self.rows(name), [[str(item) for item in row] for row in rows], name)

    def test_manifest(self):
        for line in (PACKET / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
