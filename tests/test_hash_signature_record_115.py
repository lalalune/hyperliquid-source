import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import hash_signature_record_115 as tool  # noqa: E402

FIRST, TWIN = 0x27606D0, 0x2760BC0


def _load(cls):
    cls.image = tool.load_image()
    cls.cases = tool.cases()
    cls.consts = {start: tool.body_constants(cls.image, start) for start in tool.BODIES}


def flipped(image, va):
    """Copy of the image with the jcc at `va` inverted."""
    for site, off in tool.jcc_sites(image, tool.body_insns(image, FIRST if va < TWIN else TWIN)[0]):
        if site == va:
            data = bytearray(image.data)
            data[off] ^= 1
            out = copy.copy(image)
            out.data, out.cache = bytes(data), {}
            return out
    raise AssertionError(f"no jcc at {va:#x}")


class HashSignatureRecordTest(unittest.TestCase):
    setUpClass = classmethod(_load)

    def same(self, image, start, case, consts=None):
        got = tool.normalize(tool.run_body(image, start, case))
        want = tool.normalize(tool.record(case, *(consts or self.consts[start])))
        return got == want

    def test_locations_from_bytes(self):
        rows = tool.locations(self.image)
        self.assertEqual(len(rows), 8)
        self.assertIn((0x643B2F0, 107, 28), rows)
        self.assertIn((0x643B308, 123, 32), rows)

    def test_report_constants_differ_between_twins(self):
        self.assertEqual(self.consts[FIRST], (10, 0x643B2F0, 0x643B308))
        self.assertEqual(self.consts[TWIN], (11, 0x643B2F0, 0x643B308))

    def test_fde_bounds(self):
        lo, hi, insns = tool.body_insns(self.image, FIRST)
        self.assertEqual((lo, hi), (0x27606D0, 0x2760BBC))
        self.assertEqual(len(insns), 260)

    def test_reconstruction_matches_sampled_cases(self):
        for start in tool.BODIES:
            for case in self.cases[::9]:
                self.assertTrue(self.same(self.image, start, case), (hex(start), tool.describe(case)))

    def test_error_word_and_ok_false(self):
        base = dict(self.cases[0], signer=None, check=None, pred=0)
        got = tool.run_body(self.image, FIRST, base)
        self.assertEqual((got[1], got[2]), (tool.ERR_TAG, 0xEE))
        got = tool.run_body(self.image, FIRST, dict(base, pred=1))
        self.assertEqual((got[1], got[2]), (tool.OK_TAG, 0))

    def test_old_entry_sets_flag_and_watermark(self):
        case = next(c for c in self.cases if c["old"] is not None and c["check"] is not None)
        got = tool.run_body(self.image, FIRST, case)
        self.assertEqual((got[1], got[2]), (tool.OK_TAG, 1))
        self.assertIn("watermark", [row[0] for row in got[4]])

    # negative controls

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
            tool.body_insns(self.image, FIRST + 4)

    def test_rejects_address_outside_fdes(self):
        with self.assertRaises(tool.cpu.ToolError):
            tool.body_insns(self.image, 0x10)

    def test_flipped_seal_branch_is_caught(self):
        mutant = flipped(self.image, 0x2760749)
        caught = sum(not self.same(mutant, FIRST, c, self.consts[FIRST]) for c in self.cases[::5])
        self.assertGreater(caught, 0)

    def test_flipped_membership_branch_is_caught(self):
        mutant = flipped(self.image, 0x276084C)
        caught = sum(not self.same(mutant, FIRST, c, self.consts[FIRST]) for c in self.cases[::3])
        self.assertGreater(caught, 0)

    def test_wrong_report_code_is_caught(self):
        case = next(c for c in self.cases if c["prior"] is not None and c["check"] is not None)
        self.assertTrue(self.same(self.image, FIRST, case))
        self.assertFalse(self.same(self.image, FIRST, case, self.consts[TWIN]))

    def test_wrong_reconstructions_are_caught(self):
        for variant in tool.VARIANTS:
            caught = 0
            for case in self.cases[::2]:
                real = tool.normalize(tool.run_body(self.image, FIRST, case))
                caught += real != tool.normalize(tool.record(case, *self.consts[FIRST], variant))
                if caught:
                    break
            self.assertGreater(caught, 0, variant)

    def test_corrupted_hash_input_changes_insert_log(self):
        case = next(c for c in self.cases if c["old"] is not None and c["check"] is not None)
        got = tool.run_body(self.image, FIRST, case)
        saved = tool.HASH
        tool.HASH = bytes(32)
        try:
            self.assertNotEqual(tool.normalize(got), tool.normalize(tool.record(case, *self.consts[FIRST])))
        finally:
            tool.HASH = saved


if __name__ == "__main__":
    unittest.main()
