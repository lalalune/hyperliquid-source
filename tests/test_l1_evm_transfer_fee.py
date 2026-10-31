"""Tests for tools/l1_evm_transfer_fee.py. Expected numbers here are literals, not calls to the tool's closed forms."""
import copy
import hashlib
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import l1_evm_transfer_fee as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-l1-evm-transfer-fee-94"
TOP = 2 ** 64 - 1
BEST = 0x0CCCCCCCCCCCCCCB


class Shared:
    image = None
    full = None
    sites = None


def image_get():
    if Shared.image is None:
        Shared.image = tool.load_image()
    return Shared.image


def result_get():
    if Shared.full is None:
        Shared.full = tool.analyse(image_get())
    return Shared.full


def sites_get():
    if Shared.sites is None:
        Shared.sites = tool.call_sites(image_get())
    return {slot: list(rows) for slot, rows in Shared.sites.items()}


def flip(va, mask=1):
    image = image_get()
    return {va: image.blob[image.offset(va)] ^ mask}


class Input(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_last_byte_is_refused(self):
        blob = bytearray(image_get().blob)
        blob[-1] ^= 1
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(blob)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_nobits_address_has_no_file_offset(self):
        image = image_get()
        with self.assertRaises(tool.EvidenceError):
            image.offset(image.named[".bss"]["address"])

    def test_function_bounds_come_from_fdes(self):
        image = image_get()
        self.assertEqual(image.exact_fde(0x1359660), (0x1359660, 0x13597EA))
        self.assertEqual(image.exact_fde(0x342A1B0), (0x342A1B0, 0x342A1F9))
        self.assertEqual(image.exact_fde(0x37325D0), (0x37325D0, 0x373267B))
        with self.assertRaises(tool.EvidenceError):
            image.exact_fde(0x1359661)


class NextBaseFee(unittest.TestCase):
    def run_real(self, *args):
        return tool.Harness(image_get()).run_base(*args)

    def test_block_at_target_keeps_the_fee(self):
        self.assertEqual(self.run_real(15000000, 30000000, 100000000, 8, 2), ("value", 100000000))

    def test_full_block_adds_one_eighth(self):
        self.assertEqual(self.run_real(30000000, 30000000, 100000000, 8, 2), ("value", 112500000))

    def test_empty_block_takes_one_eighth(self):
        self.assertEqual(self.run_real(0, 30000000, 100000000, 8, 2), ("value", 87500000))

    def test_rise_has_a_floor_of_one(self):
        self.assertEqual(self.run_real(15000001, 30000000, 1000, 8, 2), ("value", 1001))

    def test_fall_has_no_floor(self):
        self.assertEqual(self.run_real(14999999, 30000000, 1000, 8, 2), ("value", 1000))

    def test_fall_saturates_at_zero(self):
        self.assertEqual(self.run_real(0, 30000000, 7, 1, 2), ("value", 0))

    def test_panic_lines(self):
        self.assertEqual(self.run_real(5, 6, 7, 8, 0)[:3], ("panic", 33, 22))
        self.assertEqual(self.run_real(1, 1, 7, 8, 2)[:3], ("panic", 47, 21))
        self.assertEqual(self.run_real(9, 8, 7, 1 << 127, 2)[:3], ("panic", 48, 27))
        self.assertEqual(self.run_real(1, 8, 7, 1 << 127, 2)[:3], ("panic", 57, 23))
        self.assertEqual(self.run_real(1, 8, 7, 0, 2)[:3], ("panic", 56, 17))
        self.assertEqual(self.run_real(TOP, 2, TOP, 1, 2)[:3], ("panic", 43, 13))

    def test_quotient_past_64_bits_is_cut_to_its_low_word(self):
        # (2^64 - 1 - 1) * 2^62 / 1 has a high word; the step is the low word, here 0x8000000000000000.
        self.assertEqual(self.run_real(TOP, 2, 1 << 62, 1, 2), ("value", (1 << 62) + (1 << 63)))

    def test_step_of_exactly_two_to_the_64_adds_nothing(self):
        # Target 1, delta 4, base 2^62, divisor 1: the quotient is 2^64, so the step is 0, not 1.
        self.assertEqual(self.run_real(5, 2, 1 << 62, 1, 2), ("value", 1 << 62))

    def test_model_agrees_on_a_literal_table(self):
        self.assertEqual(tool.next_base_fee_model(1, 8, 800, 8, 2), ("value", 725))
        self.assertEqual(tool.next_base_fee_model(7, 8, 800, 8, 2), ("value", 875))


class Price(unittest.TestCase):
    def run_real(self, tag, base=1, limit=2, used=3, stale=0x1234, stub=None):
        return tool.Harness(image_get()).run_price(tag, base, limit, used, stale, stub)

    def test_floor_edge(self):
        self.assertEqual(self.run_real(1, stub=99999999)[1], 100000000)
        self.assertEqual(self.run_real(1, stub=100000000)[1], 100000000)
        self.assertEqual(self.run_real(1, stub=100000001)[1], 100000001)

    def test_callee_gets_header_words_and_fixed_parameters(self):
        got = self.run_real(1, 11, 22, 33, stub=5)
        self.assertEqual(got[2], ((33, 22, 11, 8, 0, 2, 0),))

    def test_tag_zero_never_calls(self):
        got = self.run_real(0, stale=TOP)
        self.assertEqual(got[1:], (100000000, ()))

    def test_edited_floor_fails_the_check(self):
        harness = tool.Harness(image_get(), flip(0x342A1E9))
        with self.assertRaises(tool.EvidenceError):
            tool.check_price(harness, tool.price_cases(10))


class Fee(unittest.TestCase):
    def run_real(self, *args):
        return tool.Harness(image_get()).run_fee(*args)

    def test_default_gas(self):
        self.assertEqual(self.run_real(100000000, 0, 12345), (0x186, 2000))

    def test_flag_takes_gas(self):
        self.assertEqual(self.run_real(100000000, 1, 12345), (0x186, 124))

    def test_ceil(self):
        self.assertEqual(self.run_real(10 ** 10, 1, 7), (0x186, 7))
        self.assertEqual(self.run_real(10 ** 10 + 1, 1, 7), (0x186, 8))
        self.assertEqual(self.run_real(1, 1, 1), (0x186, 1))
        self.assertEqual(self.run_real(0, 1, TOP), (0x186, 0))

    def test_cap_edge(self):
        price = BEST * 10 ** 10 // (1 << 42)
        gas = 1 << 42
        below = price * gas
        self.assertLessEqual(-(-below // 10 ** 10), BEST)
        self.assertEqual(self.run_real(price, 1, gas), (0x186, -(-below // 10 ** 10)))
        self.assertEqual(self.run_real(price + 2, 1, gas)[0], 0x14D)

    def test_high_quotient_word_is_refused(self):
        self.assertEqual(self.run_real(TOP, 1, TOP)[0], 0x14D)
        self.assertEqual(self.run_real(10 ** 10 * 2, 1, 1 << 63)[0], 0x14D)

    def test_flag_uses_bit_zero(self):
        self.assertEqual(self.run_real(100000000, 2, 12345), (0x186, 2000))

    def test_edited_default_gas_fails_the_check(self):
        harness = tool.Harness(image_get(), flip(0x37325E1))
        with self.assertRaises(tool.EvidenceError):
            tool.check_fee(harness, tool.fee_cases(10))


class Walker(unittest.TestCase):
    def test_results_are_the_literal_sets(self):
        tables = tool.walk_table(image_get())
        self.assertEqual({tool.abbreviate(row[1]) for row in tables["price"][1]}, {"return 0x5f5e100", "return next", "return stale"})
        self.assertEqual(len(tables["next_base_fee"][1]), 16)

    def test_sub_panics_are_never_reached(self):
        text = tool.render(result_get())["leaves.tsv"]
        self.assertNotIn("sub_overflow", text)
        self.assertNotIn("47:40", text)
        self.assertNotIn("56:37", text)

    def test_edited_branch_changes_the_table(self):
        baseline = tool.leaf_lines(tool.walked(image_get(), "next_base_fee")[1])
        changed = tool.leaf_lines(tool.walked(image_get(), "next_base_fee", flip(0x13596A9, 1))[1])
        self.assertNotEqual(baseline, changed)

    def test_edited_immediate_changes_the_table(self):
        baseline = tool.leaf_lines(tool.walked(image_get(), "fee")[1])
        changed = tool.leaf_lines(tool.walked(image_get(), "fee", flip(0x37325E1))[1])
        self.assertNotEqual(baseline, changed)

    def test_changed_result_set_is_refused(self):
        wanted = dict(tool.EXPECTED_RESULTS)
        wanted["fee"] = set(wanted["fee"]) | {"return 1"}
        with mock.patch.object(tool, "EXPECTED_RESULTS", wanted):
            with self.assertRaises(tool.EvidenceError):
                tool.walk_table(image_get())

    def test_wide_word_cannot_pass_a_32_bit_read(self):
        with self.assertRaises(tool.Unsupported):
            tool.narrow(tool.Path(), ("a", "limit"))

    def test_divide_without_a_tested_divisor_stops(self):
        path = tool.seed_base()
        path.regs[tool.RDI] = ("lo", ("a", "n"))
        path.regs[tool.RSI] = ("hi", ("a", "n"))
        path.regs[tool.RDX] = ("a", "low")
        path.regs[tool.RCX] = ("a", "high")
        with self.assertRaises(tool.Unsupported):
            tool.do_call(path, None, tool.SLOT_UDIV)

    def test_input_outside_every_leaf_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.match_one([], {})

    def test_leaf_evaluation(self):
        self.assertEqual(tool.ev(("ceil", ("udiv", 11, 2), ("ne0", ("rem", 11, 2))), {}), 6)
        self.assertEqual(tool.ev(("hi", ("mul", 1 << 63, 4)), {}), 2)


class Sites(unittest.TestCase):
    def test_counts(self):
        sites = sites_get()
        self.assertEqual(len(sites[tool.SLOT_BASE]), 6)
        self.assertEqual(len(sites[tool.SLOT_PRICE]), 3)
        self.assertEqual(len(sites[tool.SLOT_FEE]), 3)

    def test_parameter_forms(self):
        rows = tool.base_site_rows(image_get(), sites_get())
        self.assertEqual(sum(1 for row in rows if row[1] == "8, 2"), 4)
        self.assertEqual(sum(1 for row in rows if row[2] == "yes"), 4)

    def test_fee_site_offsets(self):
        rows = tool.fee_site_rows(image_get(), sites_get())
        self.assertEqual([row[2:] for row in rows], [(0x3128, 0x2A30, 0x3E0, 0x420), (0x3BA8, 0x34B0, 0x3E0, 0x420), (0x3128, 0x2A30, 0x3E0, 0x420)])

    def test_changed_site_count_is_refused(self):
        with mock.patch.object(tool, "EXPECTED_FEE_SITES", 4):
            with self.assertRaises(tool.EvidenceError):
                tool.fee_site_rows(image_get(), sites_get())

    def test_unpaired_sites_are_refused(self):
        sites = sites_get()
        sites[tool.SLOT_FEE] = sites[tool.SLOT_FEE][1:] + sites[tool.SLOT_FEE][:1]
        with self.assertRaises(tool.EvidenceError):
            tool.fee_site_rows(image_get(), sites)

    def test_tag_text(self):
        self.assertEqual(tool.tag_text(image_get(), 0x14D), "L1 to EVM transfer unable to compute fee")
        self.assertEqual(tool.tag_text(image_get(), 0x14C), "L1 to EVM transfer queue too long")

    def test_constants_are_read_from_bytes(self):
        wrong = (("default gas", 0x37325E0, 1, 4, 200001),)
        with mock.patch.object(tool, "CONSTANTS", wrong):
            with self.assertRaises(tool.EvidenceError):
                tool.constant_rows(image_get())

    def test_location_file(self):
        rows = tool.location_rows(image_get())
        self.assertEqual(len(rows), 8)
        self.assertEqual({row[1] for row in rows}, {"alloy-eips-0.9.2/src/eip1559/helpers.rs"})
        with mock.patch.object(tool, "CRATE", "other.rs"):
            with self.assertRaises(tool.EvidenceError):
                tool.location_rows(image_get())

    def test_changed_slot_is_refused(self):
        other = copy.copy(image_get())
        table = dict(other.relative())
        table[tool.SLOT_FEE] = 1
        other.relative = lambda: table
        with self.assertRaises(tool.EvidenceError):
            tool.slot_rows(other)


class Evidence(unittest.TestCase):
    def test_mutant_control_stops_on_a_low_step_limit(self):
        with mock.patch.object(tool, "MUTANT_STEP_LIMIT", 3):
            cases = {"next_base_fee": tool.base_cases(5), "price": tool.price_cases(5), "fee": tool.fee_cases(5)}
            with self.assertRaises(tool.EvidenceError):
                tool.run_mutants(image_get(), set(), cases)

    def test_mutation_counts(self):
        rows = result_get()["mutations"]
        self.assertEqual(sum(1 for row in rows if row[3] == "survived"), 1)
        self.assertEqual([row[1] for row in rows if row[3] == "survived"], [0x1359713])

    def test_folder_matches_the_tool(self):
        files = tool.render(result_get())
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)
        self.assertEqual({p.name for p in FOLDER.iterdir()}, set(files) | {"README.md", "MANIFEST.sha256"})

    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertEqual({line.split("  ")[1] for line in lines}, {p.name for p in FOLDER.iterdir()} - {"MANIFEST.sha256"})
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_tool_has_no_external_program(self):
        source = (ROOT / "tools" / "l1_evm_transfer_fee.py").read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)


if __name__ == "__main__":
    unittest.main()
