import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import abci_state_save_generic_115 as tool  # noqa: E402

IMAGE = tool.load_image()


def run(start, case, image=IMAGE):
    return tool.run_body(image, start, case)


class StaticFacts(unittest.TestCase):
    def test_digest_pinned(self):
        self.assertEqual(hashlib.sha256(tool.TARGET.read_bytes()).hexdigest(), tool.SHA256)

    def test_bad_digest_rejected(self):
        saved = tool.SHA256
        tool.SHA256 = "0" * 64
        try:
            with self.assertRaises(tool.Fail):
                tool.load_image()
        finally:
            tool.SHA256 = saved

    def test_fde_starts(self):
        for start in tool.BODIES:
            self.assertEqual(tool.body_insns(IMAGE, start)[0], start)

    def test_non_fde_start_rejected(self):
        with self.assertRaises(tool.Fail):
            tool.body_insns(IMAGE, tool.SAVE_A + 1)

    def test_slot_targets(self):
        self.assertEqual(IMAGE.slots[tool.SLOTS["norm"]], 0x5CAB560)
        self.assertEqual(IMAGE.slots[tool.SLOTS["prep"]], tool.PREP)
        self.assertEqual(IMAGE.slots[tool.SLOTS["write"]], tool.WRITE)

    def test_literals(self):
        consts = tool.save_consts(IMAGE, tool.SAVE_A)
        self.assertEqual(tool.rodata_bytes(IMAGE, consts["rmp"], 3), b"rmp")
        self.assertEqual(tool.rodata_bytes(IMAGE, consts["indent"], 2), b"  ")
        twin = tool.save_consts(IMAGE, tool.SAVE_B)
        self.assertEqual(tool.rodata_bytes(IMAGE, twin["rmp"], 3), b"rmp")
        self.assertEqual(tool.rodata_bytes(IMAGE, twin["indent"], 2), b"  ")


class SaveBodies(unittest.TestCase):
    def test_dev_null_skips_everything(self):
        for start in (tool.SAVE_A, tool.SAVE_B):
            self.assertEqual(run(start, tool.save_case(b"/dev/null", b"x.rmp")), ("ret", (), 0))

    def test_extension_selects_format(self):
        for start in (tool.SAVE_A, tool.SAVE_B):
            for norm, rmp in ((b"a.rmp", True), (b"a.RMP", True), (b"a.json", False), (b".rmp", False),
                              (b"..", False), (b"a.", False), (b"rmp", False)):
                got = run(start, tool.save_case(b"p", norm))
                names = [row[0] for row in got[1]]
                self.assertEqual("ser_rmp" in names, rmp, (start, norm))
                self.assertEqual("ser_json" in names, not rmp, (start, norm))

    def test_normaliser_failure_is_json(self):
        got = run(tool.SAVE_A, tool.save_case(b"p", None))
        self.assertIn("ser_json", [row[0] for row in got[1]])
        self.assertNotIn("eq", [row[0] for row in got[1]])

    def test_prep_error_skips_write_and_frees(self):
        got = run(tool.SAVE_A, tool.save_case(b"p", b"a.rmp", prep_err=0x1234))
        self.assertEqual(got[2], 0x1234)
        self.assertEqual([row[0] for row in got[1]][-2:], ["prep", "free"])

    def test_write_error_is_returned_after_free(self):
        got = run(tool.SAVE_B, tool.save_case(b"p", b"a.json", write_err=0x99))
        self.assertEqual(got[2], 0x99)
        self.assertEqual([row[0] for row in got[1]][-3:], ["prep", "write", "free"])

    def test_oom_stops_at_allocation_failure(self):
        got = run(tool.SAVE_A, tool.save_case(b"p", b"a.json", oom=1))
        self.assertEqual(got[0], "oom")
        self.assertEqual(got[1][-1], ("oom", 1, 0x80))

    def test_json_capacity_marker_is_an_error(self):
        got = run(tool.SAVE_A, tool.save_case(b"p", b"a.json", cap=tool.NONE_CAP))
        self.assertEqual(got[2], tool.ERR_A_RET)
        self.assertNotIn("prep", [row[0] for row in got[1]])
        got = run(tool.SAVE_A, tool.save_case(b"p", b"a.rmp", cap=tool.NONE_CAP))
        self.assertIn("prep", [row[0] for row in got[1]])

    def test_twins_agree(self):
        for case in tool.save_cases()[::97]:
            a, b = run(tool.SAVE_A, case), run(tool.SAVE_B, case)
            self.assertEqual([r[0] for r in a[1]], [r[0] for r in b[1]])
            self.assertEqual(a[2], b[2])

    def test_reconstruction_matches_sample(self):
        for start in (tool.SAVE_A, tool.SAVE_B):
            for case in tool.save_cases()[::53]:
                self.assertEqual(run(start, case), tool.reconstruct(IMAGE, start, case))


class FileHelpers(unittest.TestCase):
    def test_prep_existing_directory_does_nothing(self):
        got = run(tool.PREP, tool.fs_case(b"a/b", isdir=1))
        self.assertEqual(got[2], 0)
        self.assertNotIn("mkdir", [row[0] for row in got[1]])

    def test_prep_only_low_byte_of_isdir_counts(self):
        got = run(tool.PREP, tool.fs_case(b"a/b", isdir=0x100))
        self.assertIn("mkdir", [row[0] for row in got[1]])

    def test_prep_creates_with_mode_0777_recursive(self):
        got = run(tool.PREP, tool.fs_case(b"a/b"))
        mk = [row for row in got[1] if row[0] == "mkdir"][0]
        self.assertEqual(mk[2:4], (0x1FF, 1))

    def test_prep_mkdir_error_goes_through_converter(self):
        got = run(tool.PREP, tool.fs_case(b"a/b", mkdir_err=77))
        self.assertEqual(got[2], tool.ERR_RET)
        self.assertEqual(got[1][-1][0], "err")

    def test_prep_parent_only_for_tags_7_to_9(self):
        for tag in range(0, 12):
            got = run(tool.PREP, tool.fs_case(b"a/b", tag=tag, parent=5))
            self.assertEqual("parent" in [r[0] for r in got[1]], tag in (7, 8, 9), tag)

    def test_write_open_error_skips_directory_work(self):
        got = run(tool.WRITE, tool.fs_case(b"a/b", open_err=9, join_cap=0x20))
        names = [row[0] for row in got[1]]
        self.assertEqual(got[2], tool.ERR2_RET)
        self.assertNotIn("norm", names)
        self.assertEqual(names[-1], "free")

    def test_write_renames_onto_original_path(self):
        got = run(tool.WRITE, tool.fs_case(b"a/b", tag=9, parent=3, tp_kind=0, isdir=1))
        rename = [row for row in got[1] if row[0] == "rename"][0]
        self.assertEqual(rename[3:], (tool.PATH_ADDR, 3))

    def test_write_mkdir_error_skips_rename(self):
        got = run(tool.WRITE, tool.fs_case(b"a/b", mkdir_err=4))
        self.assertEqual(got[2], tool.ERR1_RET)
        self.assertNotIn("rename", [row[0] for row in got[1]])

    def test_reconstruction_matches_sample(self):
        for start, cases in ((tool.PREP, tool.prep_cases()), (tool.WRITE, tool.write_cases())):
            for case in cases[::41]:
                self.assertEqual(run(start, case), tool.reconstruct(IMAGE, start, case))


class EqualityHelper(unittest.TestCase):
    def test_real_comparison_matches_model(self):
        for a, b in tool.eq_cases()[::7]:
            self.assertEqual(tool.run_eq(IMAGE, a, b), ("ret", tool.model_eq(a, b)))


class NegativeControls(unittest.TestCase):
    def test_every_wrong_model_is_caught(self):
        for start, names in tool.VARIANTS.items():
            cases = tool.case_groups()[start]
            for name in names:
                caught = any(tool.reconstruct(IMAGE, start, c, name) != run(start, c) for c in cases)
                self.assertTrue(caught, (hex(start), name))

    def test_wrong_equality_models_are_caught(self):
        for name in tool.EQ_VARIANTS:
            caught = any(tool.model_eq(a, b, name) != tool.run_eq(IMAGE, a, b)[1] for a, b in tool.eq_cases())
            self.assertTrue(caught, name)

    def test_flipped_jump_changes_behaviour(self):
        jump = tool.jcc_sites(IMAGE, tool.PREP)[0]
        mutant = tool.flipped(IMAGE, jump[1])
        differs = any(run(tool.PREP, c, mutant) != run(tool.PREP, c) for c in tool.prep_cases()[::13])
        self.assertTrue(differs)

    def test_corrupted_image_digest_is_not_accepted(self):
        data = bytearray(tool.TARGET.read_bytes()[:64])
        data[0] ^= 1
        self.assertNotEqual(hashlib.sha256(bytes(data)).hexdigest(), tool.SHA256)

    def test_out_of_range_address_rejected(self):
        with self.assertRaises(Exception):
            tool.body_insns(IMAGE, 0x10)

    def test_unknown_callee_stops_the_run(self):
        case = tool.save_case(b"p", b"a.rmp")
        m = tool.Machine(IMAGE, case, tool.SAVE_A)
        m.roles = {}
        tool.setup(m, case, tool.SAVE_A)
        with self.assertRaises(tool.cpu.Done):
            m.pc = tool.SAVE_A
            for _ in range(500):
                m.step()


class Generation(unittest.TestCase):
    def test_generate_is_deterministic_and_clean(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            sa, sb = tool.generate(a), tool.generate(b)
            self.assertEqual(sa["mismatches"], 0)
            self.assertEqual(sa["mutants"]["survived"], 0)
            self.assertGreaterEqual(sa["measure"]["cases"], 10000)
            self.assertGreaterEqual(sa["measure"]["negative_controls"], 30)
            self.assertEqual(sa["measure"]["negative_controls"], sa["measure"]["negative_detected"])
            self.assertTrue(sa["save_twins_agree"])
            for name in ("cases.tsv", "mutants.tsv", "calls.tsv", "summary.json", "measure.json"):
                self.assertEqual((pathlib.Path(a) / name).read_bytes(), (pathlib.Path(b) / name).read_bytes())
            self.assertEqual(json.loads((pathlib.Path(a) / "measure.json").read_text()), sa["measure"])


if __name__ == "__main__":
    unittest.main()
