import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import node_env_args_115 as tool  # noqa: E402

core = tool.core


class EnvArgsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = core.load_image()
        cls.cases = list(tool.case_stream(330))

    def test_rule_utf8_matches_python_decoder(self):
        for data in (b"", b"abc", b"\xc3\xa9", b"\xe2\x82", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe0\x80\x80", b"\xc0\x80", b"a\xffb"):
            try:
                data.decode("utf-8")
                self.assertIsNone(tool.utf8_error(data), data)
            except UnicodeDecodeError:
                self.assertIsNotNone(tool.utf8_error(data), data)
        for case in tool.validate_edge_cases():
            try:
                case.raw.decode("utf-8")
                valid = True
            except UnicodeDecodeError:
                valid = False
            self.assertEqual(tool.utf8_error(case.raw) is None, valid, case.raw)

    def test_bytes_agree_with_rules_on_every_kind(self):
        harness = tool.Harness(self.image)
        kinds = set()
        for case in self.cases:
            _, got = harness.run(case)
            self.assertEqual(got, tool.spec_run(case))
            kinds.add(case.kind)
        self.assertEqual(kinds, {tool.COLLECT, tool.NEXT, tool.VALIDATE, tool.DROP})

    def test_known_collect_rows_and_panic_shapes(self):
        harness = tool.Harness(self.image)
        _, got = harness.run(tool.Case(tool.COLLECT, argv=[b"hl-node", b"", b"--chain"]))
        self.assertEqual(got[0], "ok")
        self.assertEqual([row[0] for row in got[2]], [7, 0, 7])
        self.assertEqual(got[2][1][1], 1)
        _, got = harness.run(tool.Case(tool.COLLECT, argc=tool.MAX_COUNT + 1))
        self.assertEqual(got[0], "panic")
        _, got = harness.run(tool.Case(tool.NEXT, elements=[(4, tool.STRINGS_AT, 2, b"\xff\xfe")], cursor=0))
        self.assertEqual(got[0], "panic")
        self.assertEqual(got[3:5], (tool.UNWRAP_MESSAGE_AT, 43))

    def test_edited_bytes_are_detected(self):
        # flipping the first conditional of the next body must change the outcome of some case
        start, end = self.image.exact_fde(tool.NEXT)
        rows = core.decode_range(self.image, start, end)
        jcc = next(row for row in rows if row.op == "jcc")
        data = self.image.blob[self.image.offset(jcc.va):][:jcc.size]
        at = jcc.size - 5 if jcc.size >= 6 else 0
        harness = tool.Harness(self.image, {jcc.va + at: data[at] ^ 1})
        harness.machine.step_limit = 5000
        wrong = 0
        for case in self.cases:
            if case.kind != tool.NEXT:
                continue
            if not tool.agrees(harness, case, tool.spec_run(case)):
                wrong += 1
        self.assertGreater(wrong, 0)

    def test_every_wrong_rule_is_caught(self):
        harness = tool.Harness(self.image)
        detect = [(case, harness.run(case)[1]) for case in tool.case_stream(1400)]
        for variant, verdict, _ in tool.variant_controls(detect):
            self.assertEqual(verdict, "killed", variant)

    def test_structural_refusals(self):
        with self.assertRaises(core.EvidenceError):
            self.image.exact_fde(tool.COLLECT + 1)
        with self.assertRaises(core.EvidenceError):
            core.load_image(core.BINARY, "0" * 64)
        with self.assertRaises(core.EvidenceError):
            self.image.exact_fde(tool.UNWRAP_MESSAGE_AT)

    def test_slots_resolve_to_the_bodies(self):
        relative = self.image.relative()
        self.assertEqual(relative[tool.SLOT_VALIDATOR], tool.VALIDATE)
        self.assertEqual(relative[0x64E1290], tool.COLLECT)
        self.assertEqual(relative[0x64E1298], tool.NEXT)


class BranchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = core.load_image()
        cls.harness = tool.Harness(cls.image)

    def run_case(self, case):
        _, got = self.harness.run(case)
        self.assertEqual(got, tool.spec_run(case))
        return got

    def test_null_argv_gives_the_empty_iterator(self):
        got = self.run_case(tool.Case(tool.COLLECT, null_argv=True, argc=5))
        self.assertEqual(got[1], (8, 8, 0, 8))
        self.assertEqual(got[2], ())
        self.assertEqual(got[3], [])

    def test_zero_count_does_not_allocate(self):
        got = self.run_case(tool.Case(tool.COLLECT, argv=[], argc=0))
        self.assertEqual(got[1], (8, 8, 0, 8))
        self.assertEqual(got[3], [])

    def test_null_entry_ends_collection_early(self):
        got = self.run_case(tool.Case(tool.COLLECT, argv=[b"a", None, b"c"], argc=3))
        self.assertEqual(len(got[2]), 1)
        self.assertEqual(got[1][2], 3)
        self.assertEqual(got[1][3] - got[1][0], 24)

    def test_first_allocation_failure_is_an_alloc_error(self):
        got = self.run_case(tool.Case(tool.COLLECT, argv=[b"a"], fail=0))
        self.assertEqual(got[0], "panic")
        self.assertEqual(got[1][-1], ("alloc_error", 8, 24))

    def test_string_allocation_failure_names_the_length(self):
        got = self.run_case(tool.Case(tool.COLLECT, argv=[b"abcd"], fail=1))
        self.assertEqual(got[1][-1], ("alloc_error", 1, 4))

    def test_empty_argument_uses_the_dangling_pointer(self):
        got = self.run_case(tool.Case(tool.COLLECT, argv=[b""]))
        self.assertEqual(got[2], ((0, 1, 0, b""),))
        self.assertNotIn("memcpy", [entry[0] for entry in got[3]])

    def test_count_above_the_product_limit_is_refused_before_allocation(self):
        got = self.run_case(tool.Case(tool.COLLECT, argc=tool.MAX_COUNT + 1))
        self.assertEqual(got[0], "panic")
        self.assertNotIn("malloc", [entry[0] for entry in got[1]])

    def test_next_on_an_exhausted_iterator_is_none(self):
        got = self.run_case(tool.Case(tool.NEXT, elements=[(3, tool.STRINGS_AT, 3, b"abc")], cursor=1))
        self.assertEqual(got, ("none", 1))

    def test_next_none_tag_advances_the_cursor(self):
        got = self.run_case(tool.Case(tool.NEXT, elements=[(tool.NONE_TAG, tool.STRINGS_AT, 0, b"")], cursor=0))
        self.assertEqual(got, ("none", 1))

    def test_next_returns_the_triple_for_valid_text(self):
        got = self.run_case(tool.Case(tool.NEXT, elements=[(9, tool.STRINGS_AT, 2, "é".encode())], cursor=0))
        self.assertEqual(got, ("some", 1, (9, tool.STRINGS_AT, 2)))

    def test_next_panics_with_the_unwrap_triple(self):
        got = self.run_case(tool.Case(tool.NEXT, elements=[(6, tool.STRINGS_AT, 3, b"a\xc3")], cursor=0))
        self.assertEqual(got[0], "panic")
        self.assertEqual(got[2], (6, tool.STRINGS_AT, 3))
        self.assertEqual(got[5:], (tool.UNWRAP_VTABLE, tool.UNWRAP_LOCATION))

    def test_validator_reports_offsets_and_truncation(self):
        self.assertEqual(self.run_case(tool.Case(tool.VALIDATE, raw=b"ab\xe2\x82")), ("err", (2, None)))
        self.assertEqual(self.run_case(tool.Case(tool.VALIDATE, raw=b"a\xffb")), ("err", (1, 1)))
        self.assertEqual(self.run_case(tool.Case(tool.VALIDATE, raw=b"\xe2(\xa1")), ("err", (0, 1)))
        self.assertEqual(self.run_case(tool.Case(tool.VALIDATE, raw=b"")), ("ok",))

    def test_validator_rejects_overlong_surrogate_and_range_overflow(self):
        for raw in (b"\xc0\x80", b"\xe0\x80\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80"):
            self.assertEqual(self.run_case(tool.Case(tool.VALIDATE, raw=raw))[0], "err", raw)

    def test_validator_accepts_four_byte_text_in_a_long_run(self):
        raw = b"x" * 40 + "\U0001f600".encode() + b"y" * 33
        self.assertEqual(self.run_case(tool.Case(tool.VALIDATE, raw=raw)), ("ok",))

    def test_drop_frees_nonzero_capacities_then_the_buffer(self):
        got = self.run_case(tool.Case(tool.DROP, elements=[(0, 1, 0, b""), (5, tool.STRINGS_AT, 0, b""), (7, tool.STRINGS_AT + 64, 0, b"")], cursor=4))
        self.assertEqual([entry[2] for entry in got[1]], [5, 7, 96])

    def test_drop_of_an_unallocated_vector_frees_nothing(self):
        got = self.run_case(tool.Case(tool.DROP, elements=[], cursor=0))
        self.assertEqual(got, ("ok", []))

    def test_wrong_rule_for_drop_is_caught(self):
        case = tool.Case(tool.DROP, elements=[(5, tool.STRINGS_AT, 0, b"")], cursor=2)
        _, got = self.harness.run(case)
        self.assertNotEqual(tool.spec_variant(case, "drop-skips-buffer"), got)


class StreamTests(unittest.TestCase):
    def test_stream_is_deterministic(self):
        first = [(c.kind, c.argv, c.argc, c.fail, c.elements, c.cursor, c.raw) for c in tool.case_stream(500)]
        second = [(c.kind, c.argv, c.argc, c.fail, c.elements, c.cursor, c.raw) for c in tool.case_stream(500)]
        self.assertEqual(first, second)

    def test_stream_length_is_exact(self):
        self.assertEqual(sum(1 for _ in tool.case_stream(1234)), 1234)

    def test_stream_covers_all_four_kinds_early(self):
        self.assertEqual({c.kind for c in tool.case_stream(400)}, {tool.COLLECT, tool.NEXT, tool.VALIDATE, tool.DROP})

    def test_argument_strings_never_contain_nul(self):
        for case in tool.case_stream(2000):
            for entry in case.argv:
                self.assertTrue(entry is None or b"\0" not in entry)

    def test_lcg_is_bounded(self):
        rng = tool.Lcg(5)
        self.assertTrue(all(0 <= rng.next(7) < 7 for _ in range(200)))

    def test_evidence_function_digests_match_the_bytes_when_present(self):
        path = ROOT / "research" / "work-items" / "node-runtime-env-args-collect-115" / "functions.tsv"
        if not path.exists():
            return
        image = core.load_image()
        import hashlib
        for line in path.read_text().splitlines()[1:]:
            name, entry, start, end, size, _, _, digest = line.split("\t")
            offset = image.offset(int(start, 16))
            self.assertEqual(hashlib.sha256(image.blob[offset:offset + int(size)]).hexdigest(), digest, name)

    def test_slot_roles_are_unique(self):
        slots = [slot for slot, _ in tool.SLOT_ROLES]
        self.assertEqual(len(slots), len(set(slots)))

    def test_wrong_validator_rule_is_caught_on_a_surrogate(self):
        harness = tool.Harness(core.load_image())
        case = tool.Case(tool.VALIDATE, raw=b"\xed\xa0\x80")
        _, got = harness.run(case)
        self.assertNotEqual(tool.spec_variant(case, "utf8-allow-surrogate-ed"), got)

    def test_wrong_collect_rule_is_caught_on_capacity(self):
        harness = tool.Harness(core.load_image())
        case = tool.Case(tool.COLLECT, argv=[b"ab"])
        _, got = harness.run(case)
        self.assertNotEqual(tool.spec_variant(case, "collect-capacity-is-length-plus-one"), got)


if __name__ == "__main__":
    unittest.main()
