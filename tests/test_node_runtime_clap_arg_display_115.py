import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import node_runtime_clap_arg_display_115 as tool  # noqa: E402


def arg(**kw):
    base = {"skinny": False, "long": None, "short": None, "flags": 0, "delim": None, "names": None, "num": None,
            "name": "file"}
    base.update(kw)
    return base


class ModelTests(unittest.TestCase):
    def test_flag_prefers_long_form(self):
        self.assertEqual(tool.model_flag(arg(long="chain", short=0x63)), ["--", "chain"])
        self.assertEqual(tool.model_flag(arg(short=0x63)), ["-", "c"])
        with self.assertRaises(tool.ModelPanic):
            tool.model_flag(arg())

    def test_option_separator_and_values(self):
        got = tool.model_option(arg(long="out", flags=tool.FLAG_EQUALS))
        self.assertEqual(got, ["--", "out", "=", "<", "file", ">", ""])
        multi = tool.model_option(arg(short=0x6F, flags=tool.FLAG_MULTIPLE, names={3: "b", 1: "a"}))
        self.assertEqual(multi, ["-", "o", " ", "<", "a", ">", " ", "<", "b", ">"])
        one = tool.model_option(arg(short=0x6F, flags=tool.FLAG_MULTIPLE, names={7: "a"}))
        self.assertEqual(one[-1], "...")

    def test_option_counted_values_use_the_value_delimiter(self):
        got = tool.model_option(arg(long="p", flags=tool.FLAG_DELIM, delim=0x2C, num=3))
        self.assertEqual(got, ["--", "p", " ", "<", "file", ">", ",", "<", "file", ">", ",", "<", "file", ">"])

    def test_option_missing_delimiter_panics_after_the_name_was_written(self):
        with self.assertRaises(tool.ModelPanic) as caught:
            tool.model_option(arg(long="p", flags=tool.FLAG_DELIM, num=2))
        self.assertEqual(caught.exception.written, ["--", "p", " "])

    def test_positional_joins_bracketed_names(self):
        got = tool.model_positional(arg(flags=tool.FLAG_DELIM, delim=0x7C, names={2: "x", 1: "y"}))
        self.assertEqual(got, ["<y>|<x>"])
        self.assertEqual(tool.model_positional(arg(flags=tool.FLAG_MULTIPLE)), ["<", "file", ">", "..."])

    def test_name_without_brackets(self):
        self.assertEqual(tool.model_name(arg(names={5: "a"})), ("borrowed", "a"))
        self.assertEqual(tool.model_name(arg(names={5: "a", 6: "b"})), ("owned", "<a> <b>"))
        with self.assertRaises(tool.ModelPanic):
            tool.model_name(arg(names={}))

    def test_failure_truncates_the_chunk_list(self):
        self.assertEqual(tool.apply_failure(["a", "b", "c"], 1), (1, ["a"]))
        self.assertEqual(tool.apply_failure(["a"], 5), (0, ["a"]))

    def test_setting_model(self):
        record = bytes(0x200)
        self.assertEqual(tool.model_is_set(0xA8, [3, 5], record, 1), 0)
        after = tool.model_set(0xA8, [8, 32], record, 1)
        self.assertEqual(tool.model_is_set(0xA8, [3, 5], after, 1), 1)


class ByteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image(tool.BINARY, tool.SHA256)

    def test_wrong_digest_is_rejected(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_out_of_range_address_is_rejected(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x10)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x165BC21)

    def test_templates_read_from_bytes(self):
        self.assertEqual(tool.template_text(self.image, 0x432903), ["<", "{}", ">"])
        self.assertEqual(tool.template_text(self.image, 0x447CC2), ["--", "{}", "{}"])
        self.assertEqual(tool.template_text(self.image, 0x43B857), ["{}"])

    def test_method_tables_start_after_the_display_slot(self):
        for kind, slot in tool.ACC_REG.items():
            rows = tool.method_slots(self.image, kind)
            self.assertGreaterEqual(len(rows), 26)
            self.assertEqual(rows[0][0], slot + 8)
            self.assertEqual(self.image.relative()[slot], {"flag": tool.F_FLAG, "option": tool.F_OPT,
                                                           "positional": tool.F_POS}[kind])

    def test_setting_tables_are_a_permutation_of_twenty_bits(self):
        for is_va, set_va in tool.SETTING_FUNCS.values():
            disp, bits, masks = tool.setting_tables(self.image, is_va, set_va)
            self.assertEqual(sorted(bits), list(range(20)))
            self.assertEqual(masks, [1 << b for b in bits])

    def test_classification_of_known_accessors(self):
        def klass(va):
            return tool.classify(tool.decode_range(self.image, va, self.image.exact_fde(va)[1]))

        self.assertEqual(klass(0x163B6A0), ("zero", {}))
        self.assertEqual(klass(0x163B730), ("load", {"disp": 0xE8, "width": 4}))
        self.assertEqual(klass(0x163B6B0), ("nonnull", {"disp": 0xC8}))
        self.assertEqual(klass(0x163B760), ("optslice", {"cap": 0, "ptr": 8, "len": 16}))
        self.assertIsNone(klass(0x165CD60))


class CodeAgreementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image(tool.BINARY, tool.SHA256)
        cls.rig = tool.Rig(cls.image)

    def agree(self, kind, count, seed):
        for argument, fail_at, number in tool.cases(kind, count, seed):
            want = tool.model_result(kind, argument, fail_at)
            got = self.rig.run(argument, kind, tool.Xorshift(number + 1), fail_at)
            self.assertEqual(want, got, tool.label(argument, fail_at))

    def test_flag(self):
        self.agree("flag", 120, 11)

    def test_option(self):
        self.agree("option", 160, 12)

    def test_positional(self):
        self.agree("positional", 160, 13)

    def test_name(self):
        self.agree("name", 120, 14)

    def test_writer_failure_in_the_middle_is_reported_and_leaks_nothing(self):
        argument = arg(flags=tool.FLAG_DELIM, delim=0x2C, names={1: "a", 2: "b", 3: "c"})
        for fail_at in range(0, 3):
            want = tool.model_result("positional", argument, fail_at)
            got = self.rig.run(argument, "positional", tool.Xorshift(3), fail_at)
            self.assertEqual(want, got)
            self.assertEqual(got[0], "err" if fail_at < 1 else "ok")

    def test_accessors_and_settings_agree(self):
        counters = {"accessor": 0}
        self.assertTrue(tool.check_accessors(self.image, None, counters, per_function=8))
        self.assertTrue(tool.check_bodies(self.image, None, counters, rounds=10))
        self.assertTrue(tool.check_settings(self.image, None, counters))
        self.assertGreater(counters["accessor"], 500)


class FixtureTests(unittest.TestCase):
    def test_boundary_cases_cover_deep_and_irregular_trees(self):
        for kind in ("option", "positional", "name"):
            boundary = tool.boundary_args(kind)
            deep = [a for a in boundary if a["skinny"]]
            self.assertEqual(sorted(len(a["names"]) for a in deep), list(tool.SKINNY_SIZES))
            self.assertTrue(any(a["shape"] is not None for a in boundary))
            delims = {a["delim"] for a in boundary if a["delim"] is not None}
            self.assertTrue({0x2C, 0xE9, 0x20AC, 0x10FFFF} <= delims)
        self.assertEqual(tool.boundary_args("flag"), [])

    def test_irregular_shapes_count_their_entries(self):
        self.assertEqual(tool.shape_count(("node", [("leaf", 0), ("leaf", 2)], 1)), 3)
        self.assertEqual(tool.shape_height(("node", [("node", [("leaf", 0)], 0)], 0)), 2)

    def test_every_equivalent_site_states_a_reason(self):
        self.assertGreaterEqual(len(tool.EQUIVALENT_SITES), 18)
        for va, reason in tool.EQUIVALENT_SITES.items():
            self.assertGreater(len(reason), 40, hex(va))
        self.assertIsNone(tool.equivalence_reason("join", 0x166A000))

    def test_case_stream_is_deterministic(self):
        first = [(tool.label(a, f), s) for a, f, s in tool.cases("option", 40, 9)]
        second = [(tool.label(a, f), s) for a, f, s in tool.cases("option", 40, 9)]
        self.assertEqual(first, second)


class NegativeControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image(tool.BINARY, tool.SHA256)

    def test_flipped_jump_in_the_flag_display_is_caught(self):
        # 0x165bc2e is the `je` that chooses between the long and the short form
        rig = tool.Rig(self.image, patches={0x165BC2E: 0x75})
        sample = list(tool.cases("flag", 60, 5))
        self.assertIsNotNone(tool.first_diff(rig, "flag", sample))

    def test_model_mutants_are_caught(self):
        rig = tool.Rig(self.image)
        for kind, mut in (("option", "equals_inverted"), ("positional", "join_no_brackets"), ("name", "bracket_limit")):
            sample = list(tool.cases(kind, 200, 6))
            self.assertIsNotNone(tool.first_diff(rig, kind, sample, mut), mut)

    def test_corrupted_mask_table_is_caught(self):
        rig = tool.AccessorRig(self.image)
        old = int.from_bytes(self.image.blob[self.image.offset(0x46CF60):self.image.offset(0x46CF60) + 4], "little")
        rig.m.memory.statics[0x46CF60] = old ^ 0x10
        self.assertFalse(tool.check_settings(self.image, None, {"accessor": 0}, rig, limit=1))

    def test_wrong_offset_in_an_accessor_model_is_caught(self):
        self.assertFalse(tool.check_accessors(self.image, None, {"accessor": 0}, None, True, 20, wrong="load"))

    def test_invalid_character_in_a_mutant_stops_the_rig_instead_of_crashing(self):
        rig = tool.Rig(self.image)
        argument = arg(short=0x61)
        rig.prepare(argument, "flag", tool.Xorshift(1), None)
        rig.m.memory.write(tool.STRUCT + 0xE8, 4, 0x200000)
        self.assertTrue(rig.go(tool.F_FLAG)[0].startswith("halt"))


if __name__ == "__main__":
    unittest.main()
