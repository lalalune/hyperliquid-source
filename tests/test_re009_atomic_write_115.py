import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re009_atomic_write_115 as tool  # noqa: E402

ENSURE, WRITE = tool.ENSURE, tool.WRITE
ERR = tool.ERR


def flipped(image, start, va, kind="jcc"):
    sites = tool.jcc_sites(image, start) if kind == "jcc" else tool.imm_sites(image, start)
    for site, off in sites:
        if site == va:
            return tool.mutated(image, off)
    raise AssertionError(f"no {kind} site at {va:#x}")


class AtomicWriteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.ensure_cases = list(tool.ensure_cases())
        cls.write_cases = list(tool.write_cases())

    def same(self, image, start, case, variant=None):
        return tool.run_body(image, start, case) == tool.MODELS[start](case, variant)

    # ---- facts read from the bytes

    def test_fde_bounds(self):
        self.assertEqual(tool.body_insns(self.image, ENSURE)[:2], (0x15020F0, 0x15021C2))
        self.assertEqual(tool.body_insns(self.image, WRITE)[:2], (0x15024A0, 0x15026D1))

    def test_slot_targets_from_relocations(self):
        roles = tool.role_table(self.image)
        self.assertEqual(roles["D"], 0x1500A60)
        self.assertEqual(roles["S3"], 0x1502F90)
        self.assertEqual(roles["S5"], 0x1502DA0)
        self.assertEqual(roles["S1"], 0x1501360)
        self.assertEqual(roles["free"], 0x635DE30)

    def test_call_order_of_ensure_body(self):
        roles = [row[3] for row in tool.call_rows(self.image, ENSURE)]
        self.assertEqual(roles, ["A", "B", "C", "D", "E", "F"])

    def test_call_order_of_write_body(self):
        roles = [row[3] for row in tool.call_rows(self.image, WRITE)]
        self.assertEqual(roles, ["S1", "S2", "free", "S3", "free", "S4", "W", "A", "B", "C", "D", "E", "F",
                                 "S5", "free", "free", "?"])   # "?" is the unwind-resume call of the cleanup pads

    # ---- behaviour

    def test_existing_directory_makes_no_mkdir_call(self):
        got = tool.run_body(self.image, ENSURE, tool.base_case(exists=1))
        self.assertEqual(got[1], 0)
        self.assertEqual([row[0] for row in got[2]], ["A", "D"])

    def test_mkdir_uses_mode_0x1ff_recursive(self):
        got = tool.run_body(self.image, ENSURE, tool.base_case())
        self.assertEqual(got[2][-1], ("E", tool.PATH, 4, 0x1FF, 1))

    def test_mkdir_error_word_comes_from_wrapper(self):
        got = tool.run_body(self.image, ENSURE, tool.base_case(mk=ERR, fret=0x1234))
        self.assertEqual(got[1], 0x1234)
        self.assertEqual(got[2][-1], ("F", ERR))

    def test_absolute_flag_needs_a_nonempty_path(self):
        for path, flag in ((b"/a", 1), (b"a", 0), (b"", 0)):
            got = tool.run_body(self.image, ENSURE, tool.base_case(path=path))
            self.assertEqual(got[2][0][5], flag, path)

    def test_tag_window_is_exactly_7_to_9(self):
        for tag in range(256):
            got = tool.run_body(self.image, ENSURE, tool.base_case(tag=tag, b=0x7400_0000))
            self.assertEqual("B" in [row[0] for row in got[2]], 7 <= tag <= 9, tag)

    def test_replacement_directory_is_used_unless_discriminant_is_one(self):
        for disc, replaced in ((0, True), (1, False), (2, True)):
            case = tool.base_case(tag=7, b=1, disc=disc, dir_ptr=tool.DIR, dir_len=3)
            got = tool.run_body(self.image, ENSURE, case)
            want = (tool.DIR, 3) if replaced else (tool.PATH, 4)
            self.assertEqual(got[2][-2][1:3], want, disc)

    def test_write_error_skips_directory_work_and_rename(self):
        got = tool.run_body(self.image, WRITE, tool.base_case(s4=ERR, wret=0x77, tcap=4))
        self.assertEqual(got[1], 0x77)
        roles = [row[0] for row in got[2]]
        self.assertEqual(roles, ["S1", "S2", "S3", "S4", "W", "free"])

    def test_rename_uses_the_original_path_not_the_directory(self):
        case = tool.base_case(tag=7, b=1, disc=0, dir_ptr=tool.DIR, dir_len=1, s5=0x4242)
        got = tool.run_body(self.image, WRITE, case)
        self.assertEqual(got[1], 0x4242)
        self.assertEqual(got[2][-1][0], "S5")
        self.assertEqual(got[2][-1][3:], (tool.PATH, 4))

    def test_mkdir_failure_returns_wrapper_word_without_rename(self):
        got = tool.run_body(self.image, WRITE, tool.base_case(mk=ERR, fret=0x99, s5=0x42))
        self.assertEqual(got[1], 0x99)
        self.assertNotIn("S5", [row[0] for row in got[2]])

    def test_temp_name_buffers_are_released(self):
        got = tool.run_body(self.image, WRITE, tool.base_case(s1cap=5, s2cap=9, tcap=12))
        frees = [row for row in got[2] if row[0] == "free"]
        self.assertEqual([row[2] for row in frees], [5, 9, 12])

    def test_reconstruction_matches_sampled_cases(self):
        for start, cases in ((ENSURE, self.ensure_cases), (WRITE, self.write_cases)):
            for case in cases[::7]:
                self.assertTrue(self.same(self.image, start, case), (hex(start), tool.describe(case)))

    def test_extreme_lengths_do_not_change_results(self):
        case = tool.base_case(clen=0xFFFF_FFFF_FFFF_FFFF, tlen=0xFFFF_FFFF)
        self.assertTrue(self.same(self.image, WRITE, case))

    # ---- negative controls

    def test_rejects_changed_digest(self):
        saved = tool.SHA256
        tool.SHA256 = "0" * 64
        try:
            with self.assertRaisesRegex(tool.Fail, "target digest"):
                tool.load_image()
        finally:
            tool.SHA256 = saved

    def test_rejects_non_start_address(self):
        with self.assertRaisesRegex(tool.Fail, "not an FDE start"):
            tool.body_insns(self.image, ENSURE + 4)

    def test_rejects_address_outside_fdes(self):
        with self.assertRaises(tool.cpu.ToolError):
            tool.body_insns(self.image, 0x10)

    def test_every_variant_is_caught(self):
        for start, cases in ((ENSURE, self.ensure_cases), (WRITE, self.write_cases)):
            for variant in tool.VARIANTS[start]:
                caught = any(tool.run_body(self.image, start, c) != tool.MODELS[start](c, variant)
                             for c in cases[::3])
                self.assertTrue(caught, (hex(start), variant))

    def test_flipped_exists_branch_is_caught(self):
        mutant = flipped(self.image, ENSURE, 0x1502180)
        self.assertFalse(all(self.same(mutant, ENSURE, c) for c in self.ensure_cases[::5]))

    def test_changed_mode_immediate_is_caught(self):
        mutant = flipped(self.image, ENSURE, 0x1502182, "imm")
        got = tool.run_body(mutant, ENSURE, tool.base_case())
        self.assertEqual(got[2][-1][3], 0x1FE)
        self.assertNotEqual(got, tool.ensure_model(tool.base_case()))

    def test_changed_window_bound_is_caught_only_on_tag_9(self):
        mutant = flipped(self.image, ENSURE, 0x150213B, "imm")
        for tag in (6, 7, 8, 10):
            self.assertTrue(self.same(mutant, ENSURE, tool.base_case(tag=tag, b=1)), tag)
        self.assertFalse(self.same(mutant, ENSURE, tool.base_case(tag=9, b=1)))

    def test_flipped_rename_gate_is_caught(self):
        mutant = flipped(self.image, WRITE, 0x150262E)
        self.assertFalse(all(self.same(mutant, WRITE, c) for c in self.write_cases[::5]))

    def test_unknown_callee_is_reported(self):
        roles = dict(tool.ROLES)
        del tool.ROLES["D"]
        try:
            got = tool.run_body(self.image, ENSURE, tool.base_case())
        finally:
            tool.ROLES.update(roles)
        self.assertEqual(got[0], "stop")

    def test_generated_evidence_is_self_consistent(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            summary = tool.generate(td, sample_every=997)
        self.assertEqual(summary["mismatches"], 0)
        self.assertEqual(summary["negative_controls"], summary["negative_detected"])
        self.assertGreaterEqual(summary["cases"], 10000)
        self.assertGreaterEqual(summary["negative_controls"], 30)


if __name__ == "__main__":
    unittest.main()
