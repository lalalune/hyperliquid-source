import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import book_peer_links_115 as tool  # noqa: E402


def load(cls):
    cls.image = tool.load_image()


class BookPeerLinks(unittest.TestCase):
    setUpClass = classmethod(load)

    def test_binary_digest_is_enforced(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_bodies_are_exact_fde_extents(self):
        for body in tool.BODIES:
            self.assertEqual(self.image.exact_fde(body["entry"]), (body["entry"], body["end"]))
        self.assertEqual([b["end"] - b["entry"] for b in tool.BODIES], [1497, 1497, 1604, 1604])

    def test_entry_plus_one_is_not_a_function_start(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.BODIES[0]["entry"] + 1)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x10)

    def test_bodies_decode_to_their_extent(self):
        for body in tool.BODIES:
            rows = tool.decode_body(self.image, body)
            self.assertEqual(rows[-1].next, body["end"])

    def test_twins_differ_only_in_position_dependent_bytes(self):
        rows = tool.copy_rows(self.image)
        for row in rows:
            self.assertEqual(row[2], row[3])
            self.assertEqual(row[4], 0)
            self.assertGreater(row[5], 0)

    def test_layout_constants_are_in_every_body(self):
        sites = tool.layout_sites(self.image)
        for index in range(4):
            immediates = {int(row[4], 16) for row in sites if row[0] == index and row[3] == "imm"}
            for needed in (tool.SLAB_STRIDE, tool.OT_VAL_STRIDE, tool.ORDER_RING_STRIDE, tool.USER_STRIDE, tool.VACANT):
                self.assertIn(needed, immediates)
            displacements = {int(row[4], 16) for row in sites if row[0] == index and row[3] == "disp"}
            for needed in (tool.UT_LEN, tool.OT_LEN, tool.UT_EDGES, tool.OT_EDGES, tool.BOOK_SLAB_PTR, tool.USERS_PTR):
                self.assertIn(needed, displacements)
        link = {int(row[4], 16) for row in sites if row[0] == 0 and row[3] == "disp"}
        detach = {int(row[4], 16) for row in sites if row[0] == 2 and row[3] == "disp"}
        self.assertTrue({tool.PEER_TAG, tool.PEER_ID} <= link)
        self.assertTrue({tool.PARENT_TAG, tool.PARENT_ID, tool.KIDS_PTR, tool.KIDS_LEN} <= detach)

    def test_specification_matches_the_bytes(self):
        harness = tool.new_harness(self.image)
        for body_index in range(len(tool.BODIES)):
            for number in range(40):
                ok, row = tool.run_case(harness, body_index, number)
                self.assertTrue(ok, (body_index, number))

    def test_cases_reach_every_outcome_class(self):
        rows, failures, tally = tool.run_all(self.image, 120)
        self.assertEqual(failures, [])
        kinds = {(k[0], k[3].split("-")[0]) for k in tally}
        self.assertEqual(kinds, {("link", "panic"), ("link", "writes"), ("detach", "panic"), ("detach", "writes")})
        self.assertTrue(any(k[0] == "detach" and k[3] in ("writes-3", "writes-4", "writes-6") for k in tally))

    def test_wrong_specifications_are_rejected(self):
        for variant, detected, tried in ((v[1], v[2], v[3]) for v in tool.variant_controls(self.image, 120)):
            self.assertTrue(detected, variant)

    def test_flipped_branches_are_detected(self):
        listing = tool.decode_body(self.image, tool.BODIES[0])
        jumps = [row for row in listing if row.op == "jcc"]
        self.assertGreater(len(jumps), 40)
        caught = 0
        for row in jumps[:12]:
            patches = tool.jcc_patch(self.image, row)
            if tool.killer(self.image, 0, patches, list(range(120))) is not None:
                caught += 1
        self.assertGreaterEqual(caught, 10)

    def test_corrupted_immediate_is_detected(self):
        listing = tool.decode_body(self.image, tool.BODIES[2])
        row = next(r for r in listing if r.op == "imul3" and r.target == tool.SLAB_STRIDE)
        patches = tool.imm_patch(self.image, row)
        self.assertIsNotNone(tool.killer(self.image, 2, patches, list(range(120))))

    def test_unpatched_probe_finds_nothing(self):
        for index in range(4):
            self.assertIsNone(tool.killer(self.image, index, {}, list(range(60))))

    def test_out_of_range_byte_patch_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.read_byte(0x7FFFFFFF)

    def test_case_rows_are_deterministic(self):
        first = tool.run_all(self.image, 6)[0]
        second = tool.run_all(self.image, 6)[0]
        self.assertEqual(first, second)
        self.assertEqual(len(first), 6 * len(tool.BODIES))
        self.assertEqual(len({row[:2] for row in first}), len(first))


if __name__ == "__main__":
    unittest.main()
