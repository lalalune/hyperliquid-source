import importlib.util
import json
import pathlib
import struct
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("book_insert_ring_115", ROOT / "tools" / "book_insert_ring_115.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class BookInsertRingTests(unittest.TestCase):
    image = None
    files = None

    def setUp(self):
        if BookInsertRingTests.image is None:
            BookInsertRingTests.image = tool.load_image()
        self.image = BookInsertRingTests.image

    def test_cases_match_the_bytes(self):
        harness = tool.Harness(self.image)
        for twin in range(2):
            for case in tool.cases_for(twin, 150):
                ok, expected, actual = tool.check(harness, case)
                self.assertTrue(ok, (twin, case.label))

    def test_wrong_digest_is_rejected(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_addresses_outside_or_inside_an_fde(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x10)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.OWNERS[1]["owner"] + 3)
        start, end = self.image.exact_fde(tool.OWNERS[0]["owner"])
        self.assertEqual(end - start, 663)

    def test_twins_differ_only_in_call_targets(self):
        rows = tool.twin_differences(self.image)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row[3] == "call target" for row in rows))

    def test_track_location_comes_from_the_bytes(self):
        for row in tool.OWNERS:
            at = row["owner"] + 0x1B8
            code = self.image.blob[self.image.offset(at):self.image.offset(at) + 7]
            self.assertEqual(code[:3], bytes.fromhex("4c8d05"))
            self.assertEqual(at + 7 + struct.unpack("<i", code[3:])[0], tool.TRACK_LOCATION)

    def test_negative_key_panics_before_any_callee(self):
        harness = tool.Harness(self.image)
        base = next(tool.cases_for(0, 0))
        actual = harness.run(base.patched(key=1 << 63))
        self.assertEqual(actual["events"], [])
        self.assertEqual(actual["stop"][:2], ("panic", tool.PANIC_LENGTH))

    def test_flag_byte_not_flag_word_gates_the_cache(self):
        harness = tool.Harness(self.image)
        base = next(tool.cases_for(0, 0)).patched(kind=0, flag=0x100, result=0x1234)
        actual = harness.run(base)
        flag, cached = struct.unpack_from("<QQ", actual["level"], 0)
        self.assertEqual((flag, cached), (1, 0x1234))

    def test_ring_wraps_and_grows(self):
        harness = tool.Harness(self.image)
        base = next(tool.cases_for(0, 0)).patched(kind=1, cap=4, head=3, length=3, found=0)
        actual = harness.run(base)
        self.assertEqual(struct.unpack_from("<QQQQQQ", actual["level"], 0)[2:], (4, tool.RING, 3, 4))
        self.assertEqual(actual["ring"][64:72], struct.pack("<Q", base.f0))
        grown = harness.run(base.patched(length=4))
        self.assertEqual(struct.unpack_from("<QQQQQQ", grown["level"], 0)[2:], (8, tool.GROWN, 0, 5))
        self.assertEqual(grown["events"][-1][0], "grow")

    def test_spec_variants_are_all_caught(self):
        harness = tool.Harness(self.image)
        for variant in tool.VARIANTS:
            caught = False
            for case in tool.cases_for(0, 400):
                ok, _, _ = tool.check(harness, case, variant)
                if not ok:
                    caught = True
                    break
            self.assertTrue(caught, variant)

    def test_a_flipped_branch_is_caught(self):
        start, end = self.image.exact_fde(tool.OWNERS[0]["owner"])
        flipped = 0
        for row in tool.decode_range(self.image, start, end):
            if row.op != "jcc":
                continue
            patch = tool.jcc_patch(self.image, row)
            self.assertIsNotNone(patch)
            flipped += 1
            self.assertTrue(tool.detects(self.image, {patch[0]: patch[1]}, list(tool.cases_for(0, 300))), hex(row.va))
        self.assertEqual(flipped, 5)

    def test_corrupted_spec_value_is_a_mismatch(self):
        harness = tool.Harness(self.image)
        case = next(tool.cases_for(0, 0))
        expected = tool.spec_insert(case)
        expected["ret"] ^= 1
        self.assertFalse(tool.matches(harness.run(case), expected))
        expected = tool.spec_insert(case)
        expected["events"] = expected["events"][:-1]
        self.assertFalse(tool.matches(harness.run(case), expected))

    def test_full_render_is_consistent(self):
        files = tool.render(self.image, 120, 5, 120)
        measure = json.loads(files["measure.json"])
        self.assertEqual(measure["negative_controls"], measure["negative_detected"] + measure["equivalent"])
        self.assertGreaterEqual(measure["negative_controls"], 30)
        for name, text in files.items():
            self.assertNotIn("/" + "home" + "/", text)
            self.assertNotIn("/" + "mnt" + "/", text)

    def test_twins_agree_on_every_shared_case(self):
        harness = tool.Harness(self.image)
        for case in tool.cases_for(0, 120):
            first = harness.run(case)
            second = harness.run(case.patched(twin=1))
            self.assertEqual(first.get("stop"), second.get("stop"))
            if "stop" not in first:
                self.assertEqual([first[k] for k in ("ret", "level", "ring")], [second[k] for k in ("ret", "level", "ring")])
                self.assertEqual([e[0] for e in first["events"]], [e[0] for e in second["events"]])

    def test_registration_arm_pushes_a_zero_and_no_second_stack_word(self):
        harness = tool.Harness(self.image)
        case = next(tool.cases_for(0, 0)).patched(kind=0)
        events = harness.run(case)["events"]
        insert = [event for event in events if event[0] == "insert"]
        self.assertEqual(len(insert), 1)
        self.assertEqual((insert[0][7], insert[0][8]), (0, None))
        self.assertEqual([event[0] for event in events], ["key", "lookup", "level", "insert"])

    def test_append_arm_event_order(self):
        harness = tool.Harness(self.image)
        case = next(tool.cases_for(0, 0)).patched(kind=1, found=1)
        names = [event[0] for event in harness.run(case)["events"]]
        self.assertEqual(names, ["key", "lookup", "level", "derive", "next", "insert", "track"])
        full = [event[0] for event in harness.run(case.patched(length=case.cap))["events"]]
        self.assertEqual(full, names + ["grow"])

    def test_next_exhausted_front_changes_nothing(self):
        harness = tool.NextHarness(self.image)
        case = next(case for case in tool.next_cases(200) if case.kind == "tree" and case.words[1] and case.words[1] == case.words[4]
                    and case.words[3] == case.words[6])
        actual = harness.run(case)
        self.assertEqual(actual["rax"], 0)
        self.assertEqual(actual["words"], list(case.words))

    def test_next_cases_match_the_bytes(self):
        harness = tool.NextHarness(self.image)
        for number, case in enumerate(tool.next_cases(400)):
            ok, _, _ = tool.check_next(harness, case)
            self.assertTrue(ok, (number, case.label))

    def test_next_panic_constants_come_from_the_bytes(self):
        for at, want in ((0x4E18A81, tool.PANIC_NO_FRONT_PARENT), (0x4E18A90, tool.PANIC_NO_FRONT_NODE)):
            code = self.image.blob[self.image.offset(at):self.image.offset(at) + 7]
            self.assertEqual(code[:3], bytes.fromhex("488d3d"))
            self.assertEqual(at + 7 + struct.unpack("<i", code[3:])[0], want)

    def test_next_chunk_arm_reads_only_the_low_dword_of_the_tag(self):
        harness = tool.NextHarness(self.image)
        case = tool.NextCase("list", words=(0x100000001, 0x1000, 0x1000, 0x2000, 0x2018, 5, 6))
        actual = harness.run(case)
        self.assertEqual((actual["rax"], actual["rdx"]), (0x2000, 0x2010))
        self.assertEqual(actual["words"][1:5], [0x2018, 0x2018, 0x1000, 0x1000])

    def test_next_variants_are_caught(self):
        harness = tool.NextHarness(self.image)
        for variant in tool.NEXT_VARIANTS:
            self.assertTrue(any(not tool.check_next(harness, case, variant)[0] for case in tool.next_cases(300)), variant)

    def test_next_flipped_branches_are_caught_and_the_equivalent_one_is_not(self):
        start, end = self.image.exact_fde(tool.NEXT)
        probe = list(tool.next_cases(400))
        for row in tool.decode_range(self.image, start, end):
            patch = tool.jcc_patch(self.image, row) if row.op == "jcc" else None
            if not patch:
                continue
            harness = tool.NextHarness(self.image, {patch[0]: patch[1]})
            caught = False
            for case in probe:
                try:
                    ok, _, _ = tool.check_next(harness, case)
                except Exception:
                    ok = False
                caught = caught or not ok
                if caught:
                    break
            self.assertTrue(caught, hex(row.va))
        deep = [case for case in tool.next_cases(1500) if case.label.startswith("deep")]
        self.assertGreaterEqual(len(deep), 20)
        harness = tool.NextHarness(self.image, {0x4E189EB: 9})
        self.assertTrue(all(tool.check_next(harness, case)[0] for case in deep))


if __name__ == "__main__":
    unittest.main()
