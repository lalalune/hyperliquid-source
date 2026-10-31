"""Tests for tools/mark_move_clamp.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import math
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-mark-move-clamp-94"
spec_ = importlib.util.spec_from_file_location("mark_move_clamp", ROOT / "tools" / "mark_move_clamp.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["mark_move_clamp"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None


def setUpModule():
    global IMAGE, HARNESS
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)


def edited(image, edits):
    """A copy of the image with file bytes replaced at virtual addresses."""
    clone = copy.copy(image)
    data = bytearray(image.blob)
    for va, value in edits.items():
        data[image.offset(va)] = value
    clone.blob = bytes(data)
    return clone


def byte_at(va):
    return IMAGE.blob[IMAGE.offset(va)]


def mark(new, previous=1000, daily=None, **extra):
    case = tool.one(1, new, previous, previous if daily is None else daily, **extra)
    got = HARNESS.run_case(case)
    return got, tool.spec(case)


def stored(got):
    return dict(got[2])[(tool.ASSET, 1)][0]


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_last_byte_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(IMAGE.blob[:-1] + bytes([IMAGE.blob[-1] ^ 1]))
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_nobits_never_resolves(self):
        section = IMAGE.named[".bss"]
        self.assertEqual(section["type"], 8)
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(section["address"] + 16)

    def test_fde_bounds(self):
        self.assertEqual(IMAGE.exact_fde(tool.COPY_A), (0x21FF400, 0x22001D1))
        self.assertEqual(IMAGE.exact_fde(tool.COPY_B), (0x42D0250, 0x42D1021))
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.COPY_A + 1)
        with self.assertRaises(tool.EvidenceError):
            IMAGE.fde(0x10)

    def test_copies_match(self):
        self.assertEqual(tool.copies_match(IMAGE), (691, 73))

    def test_changed_copy_is_found(self):
        site = 0x21FF4E0 + tool.DELTA + 3
        with self.assertRaises(tool.EvidenceError):
            tool.copies_match(edited(IMAGE, {site: byte_at(site) ^ 1}))

    def test_constants_pinned(self):
        self.assertEqual(len(tool.constant_rows(IMAGE)), 9)
        self.assertGreater(tool.GATE, tool.HIGH)
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(edited(IMAGE, {0x20A188: byte_at(0x20A188) ^ 1}))

    def test_kind_text_pinned(self):
        self.assertEqual([row[4] for row in tool.kind_rows(IMAGE)], list(tool.KIND_NAMES) * 2)
        at = IMAGE.relative()[tool.KIND_TABLES[tool.COPY_B][0]]
        with self.assertRaises(tool.EvidenceError):
            tool.kind_rows(edited(IMAGE, {at: byte_at(at) ^ 1}))

    def test_messages_pinned(self):
        self.assertEqual(tool.message_rows(IMAGE)["clamp"], "Price moved too far, new price is clamped")
        with self.assertRaises(tool.EvidenceError):
            tool.message_rows(edited(IMAGE, {tool.PIECES_CLAMP + 3: byte_at(tool.PIECES_CLAMP + 3) ^ 1}))

    def test_power_table_pinned(self):
        tool.power_rows(IMAGE)
        with self.assertRaises(tool.EvidenceError):
            tool.power_rows(edited(IMAGE, {tool.POWER_TABLES[tool.COPY_A] + 15: byte_at(tool.POWER_TABLES[tool.COPY_A] + 15) ^ 1}))

    def test_call_census(self):
        self.assertEqual(tool.direct_calls(IMAGE, tool.COPY_A), [0x2707CDB])
        self.assertEqual(tool.direct_calls(IMAGE, tool.COPY_B), [0x4CF3C3B, 0x4CF98DB])
        self.assertEqual(tool.direct_calls(IMAGE, tool.COPY_A + 16), [])

    def test_call_site_context(self):
        rows = tool.site_rows(IMAGE)
        self.assertEqual(len(rows), 3)
        at = 0x2707C73 + 3
        with self.assertRaises(tool.EvidenceError):
            tool.site_rows(edited(IMAGE, {at: byte_at(at) ^ 1}))

    def test_panic_locations(self):
        self.assertEqual([row[3] for row in tool.locations(IMAGE)], [194, 319])


class Paths(unittest.TestCase):
    def test_five_paths_in_both_copies(self):
        raw, kept = tool.prove_paths(IMAGE)
        self.assertEqual(len(kept), 5)
        self.assertEqual(kept, tool.prove_paths(IMAGE, tool.DELTA)[1])
        self.assertEqual(raw, 20)

    def test_swapped_gate_branch_changes_paths(self):
        at = 0x21FFAFE
        with self.assertRaises(tool.EvidenceError):
            tool.prove_paths(IMAGE, 0, {at: byte_at(at) ^ 1})

    def test_mask_compare_changes_paths(self):
        at = 0x21FF958 + 4
        with self.assertRaises(tool.EvidenceError):
            tool.prove_paths(IMAGE, 0, {at: byte_at(at) ^ 1})

    def test_changed_conversion_refused(self):
        at = 0x21FFABB + 1
        with self.assertRaises(tool.EvidenceError):
            tool.prove_paths(IMAGE, 0, {at: byte_at(at) ^ 4})

    def test_changed_conversion_constant_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.prove_paths(edited(IMAGE, {0x203E80: byte_at(0x203E80) ^ 1}))


class Outcomes(unittest.TestCase):
    def test_every_named_case(self):
        for name, case in tool.named_cases():
            for entry in (tool.COPY_A, tool.COPY_B):
                self.assertEqual(HARNESS.run_case(case, entry), tool.spec(case), name)

    def test_raw_inside_gate(self):
        got, want = mark(1010)
        self.assertEqual(got, want)
        self.assertEqual(stored(got), 1010)
        self.assertEqual(got[3], ())

    def test_clamp_up_is_stored_and_reported(self):
        got, want = mark(1011)
        self.assertEqual(got, want)
        self.assertEqual(stored(got), 1010)
        self.assertEqual(len(got[3]), 1)

    def test_clamp_down(self):
        got, want = mark(980)
        self.assertEqual(got, want)
        self.assertEqual(stored(got), 990)

    def test_spot_is_not_clamped(self):
        case = tool.one(0, 1020)
        got = HARNESS.run_case(case)
        self.assertEqual(dict(got[2])[(tool.ASSET, 0)][0], 1020)
        self.assertEqual(got[3], ())

    def test_external_is_not_clamped(self):
        case = tool.one(2, 1020)
        got = HARNESS.run_case(case)
        self.assertEqual(dict(got[2])[(tool.ASSET, 2)][0], 1020)

    def test_band_refusal_keeps_price_and_moves_time(self):
        got, want = mark(9000)
        self.assertEqual(got, want)
        price, daily, time = dict(got[2])[(tool.ASSET, 1)]
        self.assertEqual((price, daily, time), (1000, 1000, (0x11, 0x22, 0x33)))

    def test_band_is_inclusive_and_ratio(self):
        self.assertEqual(stored(mark(3000, previous=3000, daily=1000)[0]), 3000)
        low = tool.one(0, 334, 334, 1000)
        self.assertEqual(HARNESS.run_case(low)[3], ())
        self.assertEqual(len(HARNESS.run_case(tool.one(0, 333, 333, 1000))[3]), 1)
        self.assertEqual(len(HARNESS.run_case(tool.one(0, 3001, 3001, 1000))[3]), 1)

    def test_mode_three_skips_both(self):
        got, want = mark(9000, mode=3)
        self.assertEqual(got, want)
        self.assertEqual(stored(got), 9000)
        self.assertEqual(got[3], ())

    def test_previous_zero_stores_one(self):
        got, want = mark(1000, previous=0, daily=1000)
        self.assertEqual(got, want)
        self.assertEqual(stored(got), 1)

    def test_nan_passes_the_band(self):
        self.assertTrue(tool.band_admits(0, 0, 3))
        self.assertFalse(tool.band_admits(1, 0, 3))
        got = HARNESS.run_case(tool.one(0, 0, 9, 0))
        self.assertEqual(got[3], ())

    def test_saturation(self):
        got, want = mark(2 ** 64 - 1, previous=2 ** 64 - 1)
        self.assertEqual(got, want)
        got, want = mark(2 ** 64 - 1, previous=2 ** 63, daily=2 ** 63)
        self.assertEqual(got, want)
        self.assertEqual(stored(got), int(2.0 ** 63 * (1.0 + 0.01)))

    def test_wire_ids(self):
        self.assertEqual([tool.wire(value) for value in (9999, 10000, 0x5F45A5F, 0x5F45A60)], [9999, 110000, 0x5F45A5F + 100000, 0xFFFFFFFF])

    def test_small_prices_do_not_move(self):
        self.assertEqual(stored(mark(147, previous=49, daily=49)[0]), 49)
        self.assertEqual(stored(mark(150, previous=50, daily=50)[0]), 51)
        self.assertEqual(stored(mark(25, previous=50, daily=50)[0]), 50)
        self.assertEqual(stored(mark(25, previous=51, daily=51)[0]), 50)

    def test_fixed_points_real_bytes(self):
        summary = tool.fixed_summary(tool.fixed_rows(HARNESS, 80))
        self.assertEqual(summary["first_previous_moved_up"], 50)
        self.assertEqual(summary["last_unmoved_up"], 49)
        self.assertEqual(summary["first_previous_moved_down"], 51)

    def test_fixed_model(self):
        self.assertEqual(tool.fixed_model(5000), {"last_fixed_up": 49, "last_fixed_down": 50, "swept_to": 5000})

    def test_helpers_edges(self):
        self.assertEqual(tool.tail(math.nan), 1)
        self.assertEqual(tool.tail(math.inf), 1)
        self.assertEqual(tool.tail(-3.0), 1)
        self.assertEqual(tool.tail(0.4), 1)
        self.assertEqual(tool.tail(2.0 ** 64), 2 ** 64 - 1)
        self.assertEqual(tool.fround(2.5), 3.0)
        self.assertEqual(tool.fround(0.49999999999999994), 0.0)

    def test_two_copies_agree_on_vectors(self):
        for case in tool.random_cases(60, 0x1234):
            self.assertEqual(HARNESS.run_case(case, tool.COPY_A), HARNESS.run_case(case, tool.COPY_B))


class Writers(unittest.TestCase):
    def test_all_writers(self):
        rows, runs = tool.check_writers(IMAGE)
        self.assertEqual(rows[2][1], "0x4388")
        self.assertEqual(runs, 81)

    def test_flipped_max_found(self):
        at = 0x235E8C1 + 1
        with self.assertRaises(tool.EvidenceError):
            tool.check_writers(IMAGE, {at: byte_at(at) ^ 1})

    def test_length_limit_found(self):
        at = 0x235E8E8 + 3
        with self.assertRaises(tool.EvidenceError):
            tool.check_writers(IMAGE, {at: byte_at(at) ^ 1})


class Corruption(unittest.TestCase):
    def differs(self, patches, case, constants=None):
        harness = tool.Harness(IMAGE, patches, constants)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        try:
            return harness.run_case(case) != tool.spec(case)
        except (tool.Halt, tool.EvidenceError, KeyError):
            return True

    def test_gate_constant(self):
        self.assertTrue(self.differs(None, tool.one(1, 1012), {0x20A188: tool.to_bits(0.02)}))

    def test_clamp_constant(self):
        self.assertTrue(self.differs(None, tool.one(1, 1020), {0x20A2F8: tool.to_bits(0.015)}))

    def test_flag_for_mark_only(self):
        at = 0x21FF67E + 1
        self.assertTrue(self.differs({at: 0}, tool.one(1, 1020)))

    def test_mode_byte(self):
        at = 0x21FF812 + 6
        self.assertTrue(self.differs({at: byte_at(at) ^ 1}, tool.one(1, 9000, mode=3)))

    def test_floor_of_one(self):
        at = 0x21FFBF1 + 3
        self.assertTrue(self.differs({at: byte_at(at) ^ 3}, tool.one(1, 5, 1, 1, band=1000)))

    def test_kind_stride(self):
        at = 0x21FF675 + 3
        self.assertTrue(self.differs({at: byte_at(at) ^ 8}, tool.one(1, 1005)))

    def test_mutation_targets_nonempty(self):
        harness = tool.Harness(IMAGE)
        for name, case in tool.named_cases():
            harness.run_case(case)
        self.assertGreater(len(tool.mutation_targets(IMAGE, harness.machine.seen)), 150)


class Packet(unittest.TestCase):
    def test_render_is_stable(self):
        result = tool.analyse(IMAGE, full=False, vectors=40)
        first = tool.render(result)
        second = tool.render(result)
        self.assertEqual(first, second)
        self.assertIn("paths.tsv", first)

    def test_manifest_covers_every_file(self):
        names = {path.name for path in FOLDER.iterdir()} - {"MANIFEST.sha256"}
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertEqual({row.split("  ")[1] for row in rows}, names)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_no_hidden_path_marks(self):
        for path in FOLDER.iterdir():
            text = path.read_bytes()
            for word in (chr(47) + "home", chr(47) + "tmp", chr(47) + "srv", chr(47) + "mnt"):
                self.assertNotIn(word.encode(), text, path.name)


if __name__ == "__main__":
    unittest.main()
