"""Tests for tools/user_read_precompiles.py. Expected numbers here are literals, not calls to the tool's closed forms."""
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import user_read_precompiles as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-user-read-precompile-outputs-94"
TOP = 2 ** 64 - 1
E14 = 10 ** 14


class Shared:
    image = None
    harness = None
    full = None


def image_get():
    if Shared.image is None:
        Shared.image = tool.load_image()
    return Shared.image


def harness_get():
    if Shared.harness is None:
        Shared.harness = tool.Harness(image_get())
    return Shared.harness


def full_get():
    if Shared.full is None:
        Shared.full = tool.render(tool.analyse(image_get()))
    return Shared.full


def run(address, **fields):
    case = tool.Case("t", entry=tool.READERS[address], **fields)
    before, got = harness_get().run(case)
    want = tool.spec_run(case, before)
    return got, want


def words(address, **fields):
    got, want = run(address, **fields)
    if got[:5] != want[:5]:
        raise AssertionError(tool.diff_text(got, want))
    data = got[4]
    return [int.from_bytes(data[at:at + 32], "big") for at in range(0, len(data) - len(data) % 32, 32)]


def fails(patch, address, **fields):
    case = tool.Case("t", entry=tool.READERS[address], **fields)
    return tool.first_failure(tool.Harness(image_get(), patch), [case]) is not None


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
        sizes = {0x3305000: 1036, 0x3305EC0: 1035, 0x3248A20: 1151, 0x324C530: 908, 0x324ABA0: 776, 0x324BA00: 1003, 0x324A610: 1416, 0x32480A0: 2420,
                 0x3C18310: 554, 0x35935B0: 129, 0x3992540: 779, 0x3BD0820: 408, 0x3BE3530: 863}
        self.assertEqual(sorted(sizes), sorted(tool.TARGETS))
        for start, size in sizes.items():
            self.assertEqual(image.exact_fde(start), (start, start + size))
        with self.assertRaises(tool.EvidenceError):
            image.exact_fde(0x3C18311)

    def test_address_constants_are_each_functions_own(self):
        rows = {row[0]: row[3] for row in tool.constant_rows(image_get())}
        self.assertEqual(rows["0x811"], "00" * 18 + "0811")
        self.assertEqual(rows["0x804"], "00" * 18 + "0804")
        self.assertEqual(len(rows), 8)

    def test_key_text_is_one_run_in_the_file(self):
        rows = tool.key_rows(image_get())
        self.assertEqual(rows[0][1], "totalSuppliedtotalBorrowedbasisvalue")
        with self.assertRaises(tool.EvidenceError):
            saved = tool.KEY_RUNS
            tool.KEY_RUNS = (b"not in the file at all, this one",)
            try:
                tool.key_rows(image_get())
            finally:
                tool.KEY_RUNS = saved

    def test_holders(self):
        rows = {row[0]: row for row in tool.holder_rows(image_get())}
        self.assertEqual(rows["0x324a610"][2], "0x56a6ad8 0x56dfb00")
        self.assertEqual(rows["0x3c18310"][3], "0x324a957")
        self.assertEqual(rows["0x3992540"][4], "0x27db2b5 0x324c69f 0x375ecdd")


GOOD = (("shape", "leaf"), ("ia", E14 + 3), ("ib", E14 + 7))


class BoleUser(unittest.TestCase):
    def test_words_are_stored_then_scaled_for_each_lane(self):
        self.assertEqual(words(0x811, reserve=GOOD, row=(11, 3 * 10 ** 9, 13, 5 * 10 ** 9)), [11, 3 * 10 ** 9, 13, 5 * 10 ** 9])
        self.assertEqual(words(0x811, reserve=(("shape", "leaf"), ("ia", 2 * E14), ("ib", 3 * E14)), row=(1, 10, 2, 10)), [1, 20, 2, 30])

    def test_borrow_word_floors(self):
        self.assertEqual(words(0x811, reserve=(("shape", "leaf"), ("ia", E14 + 1), ("ib", E14)), row=(0, 1, 0, 0))[1], 1)
        self.assertEqual(words(0x811, reserve=(("shape", "leaf"), ("ia", E14 - 1), ("ib", E14)), row=(0, 7, 0, 0))[1], 6)

    def test_product_guard_is_exact(self):
        base = (1 << 63) + 1
        index = 199999999999999
        self.assertEqual((base * index) >> 64, E14 - 1)
        self.assertEqual(words(0x811, reserve=(("shape", "leaf"), ("ia", index), ("ib", E14)), row=(4, base, 5, 6))[:2], [4, base * index // E14])
        self.assertEqual(words(0x811, reserve=(("shape", "leaf"), ("ia", 2 * E14), ("ib", E14)), row=(4, 1 << 63, 5, 6)), [0, 0, 5, 6])

    def test_lanes_fail_alone(self):
        self.assertEqual(words(0x811, reserve=(("shape", "leaf"), ("ia", E14), ("ib", TOP)), row=(4, 6, 5, TOP)), [4, 6, 0, 0])

    def test_quotient_top_fits(self):
        self.assertEqual(words(0x811, reserve=(("shape", "leaf"), ("ia", E14), ("ib", E14)), row=(1, TOP, 2, 0)), [1, TOP, 2, 0])

    def test_missing_row_is_an_error_not_zeros(self):
        got, want = run(0x811, reserve=GOOD, row=(1, 2, 3, 4), row_shape="empty")
        self.assertEqual(got[:5], want[:5])
        self.assertEqual(want[5], "refused 0xe1 0x0")

    def test_token_bound_comes_first(self):
        self.assertEqual(run(0x811, tok=10, row_shape="empty")[1][5], "refused 0xea 0xa")

    def test_gas_saturates(self):
        got, want = run(0x811, reserve=GOOD, row=(1, 2, 3, 4), out_len=1 << 59, gas=TOP)
        self.assertEqual(got[:5], want[:5])
        self.assertEqual(want[5], "ok")
        self.assertEqual(int.from_bytes(got[1][tool.OUT - tool.HEAP_BASE + 0x20:tool.OUT - tool.HEAP_BASE + 0x28], "little"), TOP)

    def test_helper_with_no_reserve_gives_two_clear_flags(self):
        case = tool.Case("t", entry=tool.VALUES, reserve=(("shape", "miss"), ("ia", E14), ("ib", E14)), row=(1, 2, 3, 4))
        before, got = harness_get().run(case)
        self.assertEqual(got[:5], tool.spec_run(case, before)[:5])
        self.assertEqual(tool.spec_run(case, before)[5], "flags 0 0")

    def test_control_guard_edit_is_seen(self):
        self.assertTrue(fails(flip(0x3C183F6), 0x811, reserve=GOOD, row=(1, 2, 3, 4)))

    def test_control_second_index_offset_is_seen(self):
        self.assertTrue(fails(flip(0x3C184AF, 8), 0x811, reserve=GOOD, row=(1, 2, 3, 4)))


class Position(unittest.TestCase):
    def test_signed_words_extend(self):
        got = words(0x800, pos=((-16) & TOP, 7, (-32) & TOP, 9, 1))
        self.assertEqual(got, [2 ** 256 - 16, 7, 2 ** 256 - 32, 9, 1])

    def test_second_word_never_extends(self):
        self.assertEqual(words(0x813, pos=(1, 1 << 63, 2, 0xFFFFFFFF, 0)), [1, 1 << 63, 2, 0xFFFFFFFF, 0])

    def test_error_words_pass_through(self):
        got, want = run(0x800, pos=(1, 2, 3, 4, 1), pos_err=(0x31, 0x32, 0x33))
        self.assertEqual(got[:5], want[:5])
        self.assertEqual(want[5], "position error")

    def test_sibling_index_widths(self):
        self.assertEqual(words(0x800, pos=(1, 2, 3, 4, 1), perp=0xFFFF)[0], 1)
        self.assertEqual(words(0x813, pos=(1, 2, 3, 4, 1), perp=0x12345678)[0], 1)

    def test_control_sign_edit_is_seen(self):
        self.assertTrue(fails(flip(0x3305249, 1), 0x800, pos=(1 << 62, 2, 3, 4, 1)))


class SpotBalance(unittest.TestCase):
    def test_three_row_words(self):
        self.assertEqual(words(0x801, bal=(1, 2, 3)), [1, 2, 3])

    def test_absent_row_gives_zeros(self):
        for shape in ("miss", "below", "empty"):
            self.assertEqual(words(0x801, bal=(1, 2, 3), bal_shape=shape), [0, 0, 0])

    def test_token_bound(self):
        self.assertEqual(run(0x801, bal=(1, 2, 3), tok=10)[1][5], "refused 0xea 0xa")
        self.assertEqual(words(0x801, bal=(1, 2, 3), tok=9), [1, 2, 3])


class Summary(unittest.TestCase):
    def test_undelegated_nets_pending(self):
        self.assertEqual(words(0x805, sum_word=44, u=(1000, 0, 0), p=(300, 4)), [44, 700, 300, 4])

    def test_undelegated_floors_at_zero(self):
        self.assertEqual(words(0x805, sum_word=1, u=(300, 0, 0), p=(301, 1)), [1, 0, 301, 1])
        self.assertEqual(words(0x805, sum_word=1, u=(300, 0, 0), p=(300, 1)), [1, 0, 300, 1])

    def test_absent_rows(self):
        self.assertEqual(words(0x805, sum_word=1, u=(300, 0, 0), p=(9, 9), p_shape="empty"), [1, 300, 0, 0])
        self.assertEqual(words(0x805, sum_word=1, u=(300, 0, 0), p=(9, 2), u_shape="miss"), [1, 0, 9, 2])

    def test_control_saturation_edit_is_seen(self):
        self.assertTrue(fails(flip(0x399280F, 1), 0x805, u=(300, 0, 0), p=(301, 1)))


class Exists(unittest.TestCase):
    def test_every_table_shape(self):
        for kind in tool.EXISTS_HIT:
            self.assertEqual(words(0x810, exists=kind), [1], kind)
        for kind in ("empty", "twin only", "tail twin", "miss", "miss later"):
            self.assertEqual(words(0x810, exists=kind), [0], kind)


class Block(unittest.TestCase):
    def test_one_word(self):
        self.assertEqual(words(0x809, word=0xFEDCBA9876543210), [0xFEDCBA9876543210])


class Delegations(unittest.TestCase):
    def test_empty_list_is_two_words(self):
        self.assertEqual(words(0x804), [0x20, 0])

    def test_row_words(self):
        rows = ((0xA0, 0x1234, tool.day(2026, 10, 31), 50400, 5000000),)
        self.assertEqual(words(0x804, rows=rows), [0x20, 1, 0xA0, 0x1234, 1793455200005])

    def test_lock_before_epoch_is_zero(self):
        rows = ((0xA0, 1, tool.day(1969, 12, 31), 86399, 999999999),)
        self.assertEqual(words(0x804, rows=rows)[4], 0)

    def test_lock_second_part_truncates_to_ms(self):
        rows = ((0xA0, 1, tool.day(1970, 1, 1), 0, 1999999),)
        self.assertEqual(words(0x804, rows=rows)[4], 1)

    def test_year_rules(self):
        cases = (((2100, 3, 1), 4107542400000), ((2000, 3, 1), 951868800000), ((2024, 2, 29), 1709164800000))
        for (y, m, d), want in cases:
            self.assertEqual(words(0x804, rows=((0xA0, 1, tool.day(y, m, d), 0, 0),))[4], want)

    def test_rows_stay_in_key_order_at_each_height(self):
        rows = tuple((0x100 + 16 * index, index + 1, tool.day(2030, 1, 1), 0, 0) for index in range(5))
        for height in (0, 1, 8, 9, 17):
            got = words(0x804, rows=rows, height=height)
            self.assertEqual(got[2::3], [0x100, 0x110, 0x120, 0x130, 0x140], height)

    def test_user_with_no_row_gets_the_empty_list(self):
        self.assertEqual(words(0x804, rows=((1, 2, 3, 4, 5),), d_shape="miss"), [0x20, 0])

    def test_control_floor_edit_is_seen(self):
        self.assertTrue(fails(flip(0x3BE35E1, 1), 0x804, rows=((0xA0, 1, tool.day(1969, 12, 31), 0, 0),)))


class Gas(unittest.TestCase):
    def test_totals(self):
        rows = {row[0]: row for row in tool.gas_rows()}
        self.assertEqual(rows["0x800"][2], 1000 + 33 * 196)
        self.assertEqual(rows["0x801"][2], 1000 + 33 * 132)
        self.assertEqual(rows["0x804 1 rows"][2], 1000 + 33 * 196)

    def test_gas_one_short_after_output_frees_it(self):
        got, want = run(0x801, bal=(1, 2, 3), gas=1000 + 33 * 132 - 1)
        self.assertEqual(got[:5], want[:5])
        self.assertEqual(want[5], "starved after output")

    def test_control_gas_constant_edit_is_seen(self):
        self.assertTrue(fails(flip(0x3248D9D), 0x801, bal=(1, 2, 3), gas=1000 + 33 * 132))


class Packet(unittest.TestCase):
    def test_generated_files_match_the_folder(self):
        files = full_get()
        names = {path.name for path in FOLDER.iterdir()}
        self.assertEqual(names, set(files) | {"README.md", "MANIFEST.sha256"})
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest_covers_the_folder(self):
        rows = dict(line.split("  ")[::-1] for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines())
        self.assertEqual(set(rows), {path.name for path in FOLDER.iterdir()} - {"MANIFEST.sha256"})
        for name, digest in rows.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_every_mutant_is_killed_or_explained(self):
        data = json.loads(full_get()["evidence.json"])
        self.assertGreater(data["mutations"]["total"], 500)
        lines = full_get()["mutations.tsv"].splitlines()[1:]
        for line in lines:
            parts = line.split("\t")
            if parts[2] == "survived":
                self.assertNotEqual(parts[3], "UNEXPLAINED")

    def test_unedited_image_passes_a_whole_sample(self):
        self.assertIsNone(tool.first_failure(tool.Harness(image_get()), tool.vector_cases(64)))


if __name__ == "__main__":
    unittest.main()
