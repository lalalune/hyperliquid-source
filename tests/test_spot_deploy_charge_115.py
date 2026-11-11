import copy
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import spot_deploy_charge_115 as tool  # noqa: E402

cpu = tool.cpu
DATA = tool.TARGET.read_bytes()
IMAGE = cpu.Image(DATA)


def case_of(body, cls):
    for i in range(400):
        c = tool.make_case(body, i)
        if c["cls"] == cls:
            return c
    raise AssertionError(cls)


class DigestAndExtents(unittest.TestCase):
    def test_digest(self):
        self.assertTrue(tool.check_digest(DATA))

    def test_flipped_byte_fails_digest(self):
        damaged = bytearray(DATA)
        damaged[1000] ^= 4
        self.assertFalse(tool.check_digest(bytes(damaged)))

    def test_body_extents(self):
        for body, (start, size, _) in tool.BODIES.items():
            self.assertEqual(tool.body_extent(IMAGE, start), size, body)
        self.assertEqual(tool.body_extent(IMAGE, 0x2891af0), tool.LOOKUP_SIZE)
        self.assertEqual(tool.body_extent(IMAGE, 0x5a00b00), tool.LOOKUP_SIZE)

    def test_non_start_refused(self):
        with self.assertRaises(cpu.ToolError):
            tool.body_extent(IMAGE, 0x2c57091)


class ChargeSpecification(unittest.TestCase):
    def test_ceiling_division(self):
        for fee in (0, 1, 99, 100, 101, 199, 200, tool.U64, tool.U64 - 15, tool.U64 - 14):
            self.assertEqual(tool.ceil_div100(fee), -(-fee // 100), fee)

    def test_limit_text_is_35_bytes(self):
        self.assertEqual(len(tool.LIMIT_TEXT), 0x23)
        self.assertEqual(tool.LIMIT * 10000 <= tool.U64 < (tool.LIMIT + 1) * 10000, True)

    def test_each_class_is_generated(self):
        seen = {tool.make_case("A", i)["cls"] for i in range(len(tool.CLASSES))}
        self.assertEqual(seen, set(tool.CLASSES))


class MachineAgainstSpecification(unittest.TestCase):
    def test_sample_of_cases_agree(self):
        for body in tool.BODIES:
            for i in range(120):
                ok, got, _ = tool.compare(IMAGE, body, tool.make_case(body, i))
                self.assertTrue(ok, (body, i, got[:2]))

    def test_limit_boundary(self):
        c = case_of("A", "ok")
        for counter, expect in ((tool.LIMIT, "ok"), (tool.LIMIT + 1, "limit")):
            c = dict(c, counter=counter)
            ok, got, _ = tool.compare(IMAGE, "A", c)
            self.assertTrue(ok)
            self.assertEqual(got[0], expect)
            if expect == "limit":
                self.assertEqual(got[1], tool.LIMIT_TEXT)

    def test_exact_multiple_charges_exact_quotient(self):
        c = dict(case_of("C", "ok"), counter=5)
        c["fee"] = tool.ok_result(__import__("random").Random(1), tool.U64 - 15)
        c["valid"] = 1
        ok, got, _ = tool.compare(IMAGE, "C", c)
        self.assertTrue(ok)
        _, trace, _ = tool.spec("C", c)[0], tool.spec("C", c)[1], 0
        self.assertEqual(trace[-1][0], "event")
        self.assertEqual(trace[-1][-1], struct.pack("<d", -float((tool.U64 - 15) // 100) / 1e6))

    def test_zero_charge_skips_debits(self):
        c = dict(case_of("B", "ok_zero"), counter=3)
        out, trace, row = tool.spec("B", c)
        self.assertEqual(out, ("ok",))
        self.assertNotIn("debit1", [t[0] for t in trace])
        self.assertTrue(tool.compare(IMAGE, "B", c)[0])

    def test_ledger_flag_set_keeps_old_row(self):
        c = case_of("A", "flag_set")
        ok, _, _ = tool.compare(IMAGE, "A", c)
        self.assertTrue(ok)
        key = c["keys"][c["idx"]]
        self.assertEqual(tool.spec("A", c)[2], struct.unpack("<QQ", c["rows"][key][:16]))

    def test_panic_locations_are_decoded(self):
        seen = {}
        for body in tool.BODIES:
            for i in range(300):
                _, got, _ = tool.compare(IMAGE, body, tool.make_case(body, i))
                if got[0] == "panic":
                    seen[got[1]] = got[2]
        self.assertEqual(set(seen), set(tool.PANICS))
        self.assertEqual(seen["panic_debit1"][1:], (476, 18))
        self.assertEqual(seen["panic_debit2"][1:], (484, 18))
        self.assertTrue(all(v[0].endswith(".rs") for v in seen.values()))


class LookupAgainstSpecification(unittest.TestCase):
    def test_sample_of_cases_agree(self):
        for name in tool.LOOKUPS:
            for i in range(80):
                ok, got, _ = tool.lookup_compare(IMAGE, name, tool.make_lookup_case(name, i))
                self.assertTrue(ok, (name, i, got[:2]))

    def test_zero_quantity_is_refused(self):
        c = next(tool.make_lookup_case("L1", i) for i in range(16) if tool.make_lookup_case("L1", i)["cls"] == "zero")
        self.assertEqual(tool.lookup_spec(c)[0], ("zero",))
        self.assertEqual(tool.lookup_compare(IMAGE, "L1", c)[1], ("zero",))


EXITS = {
    "idx0": ("panic", "panic_idx0"), "parse_a": ("err",), "lookup": ("err",), "parse_b": ("err",),
    "idx1": ("panic", "panic_idx1"), "key": ("panic", "panic_key"), "scale": ("err",),
    "none": ("panic", "panic_none"), "limit": ("limit",), "slot": ("panic", "panic_slot"),
    "fee": ("err",), "row": ("panic", "panic_row"), "debit1": ("panic", "panic_debit1"),
    "debit2": ("panic", "panic_debit2"), "ok_zero": ("ok",), "flag_set": ("ok",),
}


def cases_of(body, cls, count):
    found = []
    for i in range(2000):
        c = tool.make_case(body, i)
        if c["cls"] == cls:
            found.append(c)
            if len(found) == count:
                return found
    raise AssertionError(cls)


class ExitTable(unittest.TestCase):
    def test_each_class_lands_on_its_exit(self):
        for body in tool.BODIES:
            for cls, expect in EXITS.items():
                for c in cases_of(body, cls, 3):
                    ok, got, _ = tool.compare(IMAGE, body, c)
                    self.assertTrue(ok, (body, cls))
                    self.assertEqual(got[0], expect[0], (body, cls))
                    if expect[0] == "panic":
                        self.assertEqual(got[1], expect[1], (body, cls))

    def test_error_records_are_forwarded_or_retagged(self):
        for body in tool.BODIES:
            for cls in ("parse_a", "lookup", "parse_b", "fee"):
                c = cases_of(body, cls, 1)[0]
                got = tool.execute(IMAGE, body, c)[0]
                self.assertEqual(got, ("err", c[cls]), (body, cls))
            c = cases_of(body, "scale", 1)[0]
            got = tool.execute(IMAGE, body, c)[0]
            self.assertEqual(got[1][:2], struct.pack("<H", 0xae))
            self.assertEqual(got[1][2:], c["scale"][2:])

    def test_ledger_row_is_marked_once(self):
        for body in tool.BODIES:
            for c in cases_of(body, "ok", 12):
                key = c["keys"][c["idx"]]
                before = struct.unpack("<QQ", c["rows"][key][:16])
                outcome, trace, row, _ = tool.execute(IMAGE, body, c)
                charge = tool.ceil_div100(tool.val_of(c["fee"]))
                expect = (1, charge) if before[0] == 0 else before
                self.assertEqual(row, expect, (body, before))

    def test_event_amount_is_negated_charge_over_a_million(self):
        for body in tool.BODIES:
            for c in cases_of(body, "ok", 6):
                charge = tool.ceil_div100(tool.val_of(c["fee"]))
                trace = tool.execute(IMAGE, body, c)[1]
                if charge:
                    self.assertEqual(trace[-1][0], "event")
                    self.assertEqual(trace[-1][-1], struct.pack("<d", float(-charge) / 1e6))
                else:
                    self.assertNotIn("debit1", [t[0] for t in trace])

    def test_context_read_only_in_mode_one(self):
        for body in tool.BODIES:
            for c in cases_of(body, "mode_other", 4):
                if tool.ceil_div100(tool.val_of(c["fee"])):
                    names = [t[0] for t in tool.execute(IMAGE, body, c)[1]]
                    self.assertNotIn("context", names)
            for c in cases_of(body, "ok", 4):
                if tool.ceil_div100(tool.val_of(c["fee"])):
                    names = [t[0] for t in tool.execute(IMAGE, body, c)[1]]
                    self.assertIn("context", names)

    def test_callee_addresses_match_the_listing(self):
        wanted = {"A": {"lookup": 0x2891af0, "scale": 0x421e9d0, "counter": 0x446bdd0, "fee": 0x38bc000},
                  "B": {"lookup": 0x5a00b00, "scale": 0x421e9d0, "counter": 0x446bdd0, "fee": 0x38bc000},
                  "C": {"lookup": 0x5a00b00, "scale": 0x421e9d0, "counter": 0x446bdd0, "fee": 0x38bc000}}
        for body, sites in wanted.items():
            c = cases_of(body, "ok", 1)[0]
            targets = tool.execute(IMAGE, body, c)[3]
            for name, target in sites.items():
                self.assertEqual(targets[name], target, (body, name))


LOOKUP_EXITS = {
    "ok": ("ok",), "ok_equal": ("ok",), "zero": ("zero",), "scale_err": ("err",),
    "idx": ("panic", "panic_idx"), "tok_a": ("panic", "panic_tok"), "tok_b": ("panic", "panic_tok"),
    "sub": ("panic", "panic_sub"),
}


class LookupExitTable(unittest.TestCase):
    def test_each_class_lands_on_its_exit(self):
        for name in tool.LOOKUPS:
            seen = set()
            for i in range(64):
                c = tool.make_lookup_case(name, i)
                ok, got, _ = tool.lookup_compare(IMAGE, name, c)
                self.assertTrue(ok, (name, i))
                expect = LOOKUP_EXITS[c["cls"]]
                self.assertEqual(got[0], expect[0], (name, c["cls"]))
                if expect[0] == "panic":
                    self.assertEqual(got[1], expect[1])
                seen.add(c["cls"])
            self.assertEqual(seen, set(LOOKUP_EXITS))

    def test_decimals_difference_is_the_scale_argument(self):
        for name in tool.LOOKUPS:
            for i in range(32):
                c = tool.make_lookup_case(name, i)
                if c["cls"] != "ok":
                    continue
                b, a = c["entries"][c["idx"]]
                trace = tool.run_lookup(IMAGE, name, c)[1]
                self.assertEqual(trace[0][3:], (2, c["toks"][a][0x49] - c["toks"][b][0x48]))

    def test_lookup_locations(self):
        seen = {}
        for name in tool.LOOKUPS:
            for i in range(64):
                got = tool.run_lookup(IMAGE, name, tool.make_lookup_case(name, i))[0]
                if got[0] == "panic":
                    seen.setdefault(got[1], set()).add(got[2])
        self.assertEqual(seen["panic_sub"], {("l1/src/spot_meta.rs", 1055, 9)})
        self.assertEqual(seen["panic_idx"], {("l1/src/spot_meta.rs", 590, 25)})
        self.assertEqual(seen["panic_tok"], {("l1/src/spot_meta.rs", 119, 33)})


class RateTable(unittest.TestCase):
    def test_known_values(self):
        table = (
            (100, 0.5, 50), (100, 1.0, 100), (3, 0.0, 0), (3, 2.5, 7), (0, 5.0, 0), (1, -1.0, 0),
            (tool.RATE_SPLIT, 1.0, tool.RATE_LIMIT), (tool.RATE_SPLIT, 0.0, 0),
            (tool.RATE_SPLIT + 1, 0.0, tool.RATE_SPLIT + 1), (7, 1e18, tool.RATE_LIMIT),
        )
        for x, mult, want in table:
            self.assertEqual(tool.rate_run(IMAGE, x, mult), want, (x, mult))
            self.assertEqual(tool.rate_spec(x, mult), want, (x, mult))

    def test_cases_are_deterministic(self):
        self.assertEqual(tool.make_case("A", 17), tool.make_case("A", 17))
        self.assertEqual(tool.make_rate_case(5), tool.make_rate_case(5))
        self.assertNotEqual(tool.make_case("A", 17)["addr"], tool.make_case("B", 17)["addr"])

    def test_inputs_above_the_split_pass_through(self):
        self.assertEqual(tool.rate_run(IMAGE, 1 << 63, -1.0), 1 << 63)
        self.assertEqual(tool.rate_run(IMAGE, tool.RATE_SPLIT, -1.0), 0)


class NegativeControls(unittest.TestCase):
    def test_every_spec_mutant_is_caught(self):
        for name, meaning in tool.SPEC_MUTANTS:
            self.assertIsNotNone(tool.run_bodies(IMAGE, 400, (name,)), name)

    def test_selected_byte_patches_are_caught(self):
        for patch in tool.BYTE_PATCHES[:6] + tool.BYTE_PATCHES[-3:]:
            self.assertIsNotNone(tool.run_bodies(tool.patched_image(IMAGE, patch), 400), patch[0])

    def test_remainder_patch_is_caught_at_the_largest_multiple(self):
        patch = [p for p in tool.BYTE_PATCHES if p[0] == "seta"][0]
        hit = tool.run_bodies(tool.patched_image(IMAGE, patch), 400)
        self.assertIsNotNone(hit)
        case = tool.make_case(*hit[:1], hit[1])
        self.assertEqual(tool.val_of(case["fee"]), tool.U64 - 15)

    def test_lookup_mutants_and_patches(self):
        for name, meaning in tool.LOOKUP_MUTANTS:
            self.assertIsNotNone(tool.lookup_run(IMAGE, 200, (name,)), name)
        for patch in tool.LOOKUP_PATCHES:
            self.assertIsNotNone(tool.lookup_run(tool.patched_lookup_image(IMAGE, patch), 200), patch[0])

    def test_clean_image_is_not_flagged(self):
        self.assertIsNone(tool.run_bodies(IMAGE, 100))
        self.assertIsNone(tool.lookup_run(IMAGE, 100))

    def test_out_of_range_inputs_are_refused(self):
        for name, meaning, detected in tool.misc_controls(IMAGE):
            self.assertTrue(detected, name)

    def test_missing_pattern_is_refused(self):
        with self.assertRaises(cpu.ToolError):
            tool.patched_image(IMAGE, ("none", b"\xde\xad\xbe\xef\xde\xad", 0, 1, "missing"))

    def test_location_decoder_rejects_plain_data(self):
        clone = copy.copy(IMAGE)
        with self.assertRaises(cpu.ToolError):
            tool.decode_location(clone, IMAGE.rodata[0] + 8)


class LeafHelpers(unittest.TestCase):
    def test_rate_early_out_and_clamps(self):
        tool_rate = lambda x, m: tool.rate_run(IMAGE, x, m)  # noqa: E731
        self.assertEqual(tool_rate(tool.RATE_SPLIT + 1, 0.5), tool.RATE_SPLIT + 1)
        self.assertEqual(tool_rate(10, 0.5), 5)
        self.assertEqual(tool_rate(10, -3.0), 0)
        self.assertEqual(tool_rate(10, float("nan")), 0)
        self.assertEqual(tool_rate(10, float("inf")), 0)
        self.assertEqual(tool_rate(10, 1e308), 0)
        self.assertEqual(tool_rate(10, 1e300), tool.RATE_LIMIT)
        self.assertEqual(tool_rate(tool.RATE_SPLIT, 1e3), tool.RATE_LIMIT)
        self.assertEqual(tool_rate(10, -(2.0 ** 63)), "panic_neg")

    def test_rate_sample_agrees(self):
        for i in range(300):
            x, mult = tool.make_rate_case(i)
            self.assertEqual(tool.rate_run(IMAGE, x, mult), tool.rate_spec(x, mult), (i, x, mult))

    def test_row_getter(self):
        self.assertEqual(tool.rowget_run(IMAGE, 3, 1000, 2), 1000 + 2 * 0x510)
        self.assertEqual(tool.rowget_run(IMAGE, 3, 1000, 3), "panic_row")
        self.assertEqual(tool.rowget_run(IMAGE, 0, 1000, 0), "panic_row")

    def test_usdc_name(self):
        self.assertEqual(tool.usdc_run(IMAGE, 0x7300_0000)[4], b"USDC")
        self.assertEqual(tool.usdc_run(IMAGE, 0), "alloc_error")

    def test_leaf_mutants_and_patches_are_caught(self):
        for name, meaning in tool.RATE_MUTANTS + (("idx_gt", ""), ("stride", "")):
            self.assertIsNotNone(tool.leaf_sweep(IMAGE, 200, (name,)), name)
        for patch in tool.LEAF_PATCHES:
            self.assertIsNotNone(tool.leaf_sweep(tool.leaf_patched(IMAGE, patch), 200), patch[0])
        self.assertIsNone(tool.leaf_sweep(IMAGE, 100))

    def test_leaf_patch_pattern_missing(self):
        with self.assertRaises(cpu.ToolError):
            tool.leaf_patched(IMAGE, ("x", tool.USDC_ENTRY, 66, b"\xde\xad\xbe\xef\xde\xad", 0, 1, "m"))


if __name__ == "__main__":
    unittest.main()
