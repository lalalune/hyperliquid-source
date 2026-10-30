import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import match_resting_order as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-match-resting-order-94"
COPY_A, COPY_B, COPY_C = tool.COPIES
BIG = tool.MASK[8]


def run(image, copy=COPY_A, patches=None, **fields):
    return tool.Harness(image, copy, patches).run(tool.Case("t", **fields))


def patched_image(image, changes):
    blob = bytearray(image.blob)
    for va, data in changes.items():
        at = image.offset(va)
        blob[at:at + len(data)] = data
    return tool.Image(bytes(blob))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()


class IdentityTests(Base):
    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_non_elf_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an x86-64 ELF"):
            tool.Image(b"\0" * 128)

    def test_interior_address_is_not_a_function_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(COPY_A[1] + 1)

    def test_address_outside_segments_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed segments"):
            self.image.offset(0x10000000000)

    def test_three_copies_decode_to_their_fde_ends_and_share_one_shape(self):
        hashes = set()
        for name, start, offsets, _, _ in tool.COPIES:
            begin, end = self.image.exact_fde(start)
            self.assertEqual(end - begin, tool.BODY_SIZE, name)
            rows = tool.decode_range(self.image, begin, end)
            self.assertEqual(rows[-1].next, end)
            digest, fields = tool.normalized_hash(self.image, begin, rows, offsets)
            self.assertEqual(fields, 4)
            hashes.add(digest)
        self.assertEqual(len(hashes), 1)

    def test_shape_hash_sees_a_changed_instruction(self):
        start = COPY_A[1]
        rows = tool.decode_range(self.image, start, start + tool.BODY_SIZE)
        clean, _ = tool.normalized_hash(self.image, start, rows, COPY_A[2])
        broken = patched_image(self.image, {start + 0x8D9: b"\x03"})
        changed, _ = tool.normalized_hash(broken, start, tool.decode_range(broken, start, start + tool.BODY_SIZE), COPY_A[2])
        self.assertNotEqual(clean, changed)

    def test_location_path_stops_at_the_crate_root(self):
        relative = self.image.relative_slots()
        path, line, column = self.image.location(COPY_A[4], relative)
        self.assertEqual((path, line, column), ("l1/src/book/book/impl_insert_order.rs", 768, 85))
        self.assertFalse(path.startswith("/"))

    def test_changed_location_line_is_seen(self):
        relative = self.image.relative_slots()
        broken = patched_image(self.image, {COPY_A[4] + 16: (769).to_bytes(4, "little")})
        self.assertEqual(broken.location(COPY_A[4], relative)[1], 769)

    def test_status_words_read_the_table(self):
        rows = tool.status_rows(self.image)
        self.assertEqual(rows[0]["text"], "Insufficient margin to place order.")
        self.assertTrue(rows[1]["text"].startswith("Order would exceed maximum position size"))
        self.assertEqual(tool.table_end(self.image), 24)

    def test_status_arm_outside_the_fde_is_rejected(self):
        broken = patched_image(self.image, {tool.STATUS_TABLE + 12: b"\0\0\0\0"})
        with self.assertRaisesRegex(tool.EvidenceError, "status arm outside"):
            tool.status_rows(broken)

    def test_changed_constants_are_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "unexpected rodata"):
            tool.constants(patched_image(self.image, {tool.DOUBLE_1E9: b"\x01"}))
        with self.assertRaisesRegex(tool.EvidenceError, "cap tail"):
            tool.constants(patched_image(self.image, {tool.CAP_TAIL[0]: b"\x90"}))

    def test_changed_leg_pin_is_rejected(self):
        broken = patched_image(self.image, {COPY_B[3] + 0xEC: b"\x90"})
        with self.assertRaisesRegex(tool.EvidenceError, "leg builder pin"):
            tool.leg_pins(broken, None)

    def test_no_external_program_is_used(self):
        source = (ROOT / "tools" / "match_resting_order.py").read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)


class ClaimTests(Base):
    """Each claim read directly from the running bytes, without the specification."""

    def test_budget_zero_returns_before_any_user_work(self):
        kind, out, trace, _ = run(self.image, budget=0, diff_at=None)
        self.assertEqual((kind, out["tag"], out["status"], out["budget"], out["reason"]), ("return", 2, tool.NONE_WORD, 0, 3))
        self.assertEqual(trace, [("drop", 0x141)])

    def test_any_of_twenty_user_bytes_separates_users(self):
        same = run(self.image, diff_at=None)[1]
        self.assertEqual((same["tag"], same["reason"]), (2, 2))
        for index in (0, 15, 16, 19):
            self.assertEqual(run(self.image, diff_at=index)[1]["tag"], 1, index)

    def test_predicate_on_both_users_blocks_the_match(self):
        self.assertEqual(run(self.image, pred_taker=True, pred_slot=True)[1]["reason"], 2)
        self.assertEqual(run(self.image, pred_taker=True, pred_slot=False)[1]["tag"], 1)
        self.assertEqual(run(self.image, pred_taker=False, pred_slot=True)[1]["tag"], 1)

    def test_first_cap_call_is_for_the_slot_user_with_no_option(self):
        trace = run(self.image)[2]
        caps = [row for row in trace if row[0] == "cap"]
        slot_user = tool.blobs(tool.Case("t"))[0][0xE0:0xF4]
        self.assertEqual(caps[0][3], slot_user)
        self.assertEqual(caps[0][6:8], (bytes(2), bytes(8)))
        self.assertEqual(caps[1][7], (10).to_bytes(8, "little"))
        self.assertEqual(caps[1][6][0], 1)

    def test_first_cap_zero_leaves_budget_and_word_alone(self):
        out = run(self.image, cap_maker=0)[1]
        self.assertEqual((out["tag"], out["status"], out["budget"], out["reason"]), (2, tool.NONE_WORD, 10, 0))

    def test_second_cap_zero_ends_the_budget_with_a_status_word(self):
        out = run(self.image, cap_taker=0, cap_other=9)[1]
        self.assertEqual((out["tag"], out["status"], out["budget"]), (2, tool.WORD_MARGIN, 0))
        out = run(self.image, cap_taker=0, cap_other=10)[1]
        self.assertEqual((out["status"], out["budget"]), (tool.WORD_POSITION, 0))

    def test_second_cap_partial_fills_and_replaces_the_budget(self):
        out = run(self.image, cap_taker=4, cap_other=9)[1]
        self.assertEqual((out["tag"], out["status"], out["budget"]), (1, tool.WORD_MARGIN, 4))
        self.assertEqual(int.from_bytes(out["fill"][0x210:0x218], "little"), 4)

    def test_budget_field_is_not_reduced_by_the_fill(self):
        out = run(self.image, budget=25, size=10)[1]
        self.assertEqual(int.from_bytes(out["fill"][0x210:0x218], "little"), 10)
        self.assertEqual(out["budget"], 25)

    def test_notional_ceiling_is_inclusive(self):
        self.assertEqual(run(self.image, price=tool.MAX_NOTIONAL, budget=1, size=1)[0], "return")
        kind, payload = run(self.image, price=tool.MAX_NOTIONAL + 1, budget=1, size=1)[:2]
        self.assertEqual((kind, payload), ("panic", ("panic", COPY_A[4])))
        self.assertEqual(run(self.image, price=1 << 32, budget=1 << 32, size=1 << 32)[0], "panic")

    def test_copy_c_panics_with_its_own_location(self):
        self.assertEqual(run(self.image, COPY_C, price=BIG, budget=2, size=2)[1], ("panic", COPY_C[4]))

    def test_mask_bits_follow_the_taker_side(self):
        for side, mask in ((0, 0x001), (1, 0x100)):
            out = run(self.image, side=side, mask=mask, cap_taker=5, cap_other=3)[1]
            self.assertEqual((out["status"], out["budget"], out["reason"]), (tool.WORD_MARGIN, 5, 0), side)
        for side, mask in ((0, 0x100), (1, 0x001)):
            out = run(self.image, side=side, mask=mask)[1]
            self.assertEqual((out["status"], out["budget"], out["reason"]), (tool.WORD_MARGIN, 0, 3), side)

    def test_reduce_only_takes_the_slot_users_position_and_side(self):
        asset = 10001
        long_case = dict(reduce_only=1, keys=(asset,), side=0, position=4, size=10, budget=10)
        out = run(self.image, **long_case)[1]
        self.assertEqual(int.from_bytes(out["fill"][0x210:0x218], "little"), 4)
        self.assertEqual(out["reason"], 1)
        wrong = dict(long_case, side=1)
        self.assertEqual(run(self.image, **wrong)[1]["reason"], 1)
        self.assertEqual(run(self.image, **wrong)[1]["tag"], 2)
        out = run(self.image, **dict(long_case, budget=3))[1]
        self.assertEqual(out["reason"], 3)

    def test_mask_wrapper_keeps_only_bit_zero_of_each_call(self):
        case = tool.MaskCase(10003, 5, 0xFE, 0xFF)
        self.assertEqual(tool.run_mask(self.image, case)[:2], ("return", 0x100))

    def test_mask_wrapper_bounds_panic(self):
        kind, details, _ = tool.run_mask(self.image, tool.MaskCase(10, 10, 1, 1))
        self.assertEqual((kind, details), ("panic", (10, 10, tool.MASK_LOCATION)))


class SpecificationTests(Base):
    def test_sample_matches_on_all_copies(self):
        cases = tool.structured_cases()[::9]
        for copy in tool.COPIES:
            failures, _, _, _ = tool.run_copy(self.image, copy, cases)
            self.assertEqual(failures, [], copy[0])

    def test_wrong_context_offsets_are_seen(self):
        wrong = (COPY_A[0], COPY_A[1], COPY_B[2], COPY_A[3], COPY_A[4])
        failures, _, _, _ = tool.run_copy(self.image, wrong, tool.structured_cases()[:40], stop_first=True)
        self.assertTrue(failures)

    def test_wrong_leg_builder_stops_the_machine(self):
        wrong = (COPY_A[0], COPY_A[1], COPY_A[2], COPY_B[3], COPY_A[4])
        failures, _, _, _ = tool.run_copy(self.image, wrong, [tool.Case("t")], stop_first=True)
        self.assertRegex(failures[0], "unmodelled call")

    def test_swapped_caps_change_the_outcome(self):
        case = tool.Case("t", cap_maker=0)
        harness = tool.Harness(self.image, COPY_A)
        self.assertIsNone(tool.compare(harness, COPY_A, case)[0])
        case_b = tool.Case("t", cap_taker=0, cap_other=BIG)
        self.assertNotEqual(harness.run(case)[1], harness.run(case_b)[1])

    def test_patched_mask_constant_is_detected(self):
        start = COPY_A[1]
        site = start + 0x8D9
        self.assertEqual(self.image.blob[self.image.offset(site):self.image.offset(site) + 4], b"\x01\x01\x00\x00")
        failures, _, _, _ = tool.run_copy(self.image, COPY_A, tool.interleaved(tool.structured_cases()),
                                          stop_first=True, patches={site: 0x03})
        self.assertTrue(failures)

    def test_every_survivor_has_a_written_reason(self):
        lines = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        rows = [line.split("\t") for line in lines]
        survived = {int(row[0], 16) for row in rows if row[2] == "survived"}
        unreached = {int(row[0], 16) for row in rows if row[2] == "unreached"}
        self.assertEqual(survived, set(tool.SURVIVOR_NOTES))
        self.assertEqual(unreached, set(tool.UNREACHED_NOTES))
        self.assertGreater(sum(1 for row in rows if row[2] == "killed"), 100)


class PacketTests(Base):
    def test_tool_reproduces_the_packet_and_manifest(self):
        with tempfile.TemporaryDirectory() as scratch:
            self.assertEqual(tool.main(["--out", scratch]), 0)
            produced = sorted(path.name for path in pathlib.Path(scratch).iterdir())
            for name in produced:
                self.assertEqual((pathlib.Path(scratch) / name).read_bytes(), (FOLDER / name).read_bytes(), name)
        listed = {}
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            listed[name] = digest
        present = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(listed), present)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(sorted(set(present) - {"README.md"}), produced)


if __name__ == "__main__":
    unittest.main()
