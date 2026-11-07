import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import const_name_flow_115 as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "constants-static-name-flow-115"
S = tool.SENTINEL
OK_DOCUMENT = (0, 33, None, 0, None)


class NameFlow115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.names = tool.read_names(cls.image, tool.NAME_ARRAYS[0])
        cls.spec = tool.Spec(cls.names)
        cls.rig = tool.Rig(cls.image)

    def same(self, runner, predict, case):
        observed, expected = runner(self.rig, case), predict(case)
        self.assertEqual(observed, expected, repr(case))
        return observed

    # -- the table itself --
    def test_two_arrays_hold_the_same_79_names(self):
        self.assertEqual(len(self.names), 79)
        self.assertEqual(self.names, tool.read_names(self.image, tool.NAME_ARRAYS[1]))
        self.assertEqual(len(set(self.names)), 79)

    def test_boundary_names_have_the_recorded_indices(self):
        for index, name in ((0, b"Ec"), (32, b"SoloSandbox"), (33, b"NvTestnet"), (34, b"NvTestnet2")):
            self.assertEqual(self.names[index], name)
            self.assertEqual(tool.real_plain(self.rig, name)[1], index)
        self.assertEqual(tool.real_plain(self.rig, b"NvTestnet")[1], 33)
        self.assertEqual(tool.real_serde(self.rig, b"NvTestnet")[2], 33)

    def test_length_buckets_cover_every_name(self):
        rows = tool.bucket_rows(self.image, self.names)
        self.assertEqual(sum(row[4] for row in rows), 79)
        start, end = self.image.exact_fde(tool.PLAIN)
        for row in rows:
            self.assertTrue(start <= int(row[2], 16) < end)
        for length in (0, 1, 14, 15, 40):
            self.same(tool.real_plain, lambda c: tool.spec_plain(self.spec, c), b"E" * length)

    # -- classifiers --
    def test_every_name_both_classifiers(self):
        for index, name in enumerate(self.names):
            self.assertEqual(self.same(tool.real_plain, lambda c: tool.spec_plain(self.spec, c), name)[1], index)
            self.assertEqual(self.same(tool.real_serde, lambda c: tool.spec_serde(self.spec, c), name)[2], index)

    def test_near_misses_are_unknown_and_report_the_table(self):
        seen = set()
        for number, (label, data) in enumerate(tool.name_inputs(self.names, 200)):
            if number % 4:
                continue
            plain = self.same(tool.real_plain, lambda c: tool.spec_plain(self.spec, c), data)
            serde = self.same(tool.real_serde, lambda c: tool.spec_serde(self.spec, c), data)
            if plain[1] == tool.UNKNOWN:
                seen.add(label)
                self.assertEqual(serde[1], 1)
                self.assertEqual(serde[3], (("unknown_variant", tool.INPUT, len(data), tool.NAME_ARRAYS[1], tool.NAME_COUNT),))
        for label in ("bit0", "case", "high", "short", "nul", "extra", "lead", "swap", "fill", "random"):
            self.assertIn(label, seen)

    def test_reads_stay_inside_the_input(self):
        for name in self.names[::6]:
            self.assertTrue(tool.real_plain(self.rig, name)[2])
            self.assertTrue(tool.real_serde(self.rig, name)[4])
            self.assertTrue(tool.real_trim(self.rig, name)[3])

    # -- trim --
    def test_every_white_space_point_and_its_neighbours(self):
        points = sorted(tool.WHITE_SPACE | {point + delta for point in tool.WHITE_SPACE for delta in (-1, 1)})
        for point in points:
            if 0xD800 <= point <= 0xDFFF:
                continue
            char = chr(point).encode()
            for data in (char, b"a" + char, char + b"a", char + b"a" + char, b"\xf0\x9f\x98\x80" + char):
                self.same(tool.real_trim, tool.spec_trim_row, data)

    def test_all_white_space_gives_the_empty_slice_at_zero(self):
        for data in (b"", b" ", " 　 \n".encode(), b"\x0b\x0c\r"):
            observed = self.same(tool.real_trim, tool.spec_trim_row, data)
            self.assertEqual(observed[1:3], (0, 0))

    def test_white_space_table_matches_the_unicode_property(self):
        start = self.image.offset(tool.WS_TABLE)
        table = bytes(self.image.blob[start:start + 256])
        tool.check_whitespace_table(table)
        for index in (0x85, 0xA0, 0x28, 0x2F, 0x00, 0x0A, 0x5F):
            broken = bytearray(table)
            broken[index] ^= 3
            with self.assertRaises(tool.EvidenceError):
                tool.check_whitespace_table(broken)

    def test_python_strip_is_not_the_specification(self):
        data = b"\x1fabc\x1f"
        self.assertEqual(tool.spec_trim(data), (0, 5))
        self.assertEqual(tool.real_trim(self.rig, data)[1:3], (0, 5))

    # -- flows --
    def test_missing_name_reader(self):
        spec = self.spec
        for case, kind in (((0, 0, b"NvTestnet\n", 0), "ret"), ((24, 0, b"  SoloSandbox ", 16), "ret"),
                           ((24, S, b"", 0), "panic"), ((0, 0, b"nvtestnet", 0), "panic"), ((8, 0, b"", 16), "panic"),
                           ((0, 0, " 　EaTx ".encode(), 32), "ret")):
            observed = self.same(tool.real_missing, lambda c: tool.spec_missing(spec, c), case)
            self.assertEqual(observed[0], kind)
        read_error = tool.real_missing(self.rig, (24, S, b"", 0))
        self.assertEqual(read_error[1], tool.PANIC_READ)
        self.assertEqual(read_error[2], (("path",), ("read", tool.PATH_AT, 9), ("free", tool.PATH_AT, 24, 0)))
        unknown = tool.real_missing(self.rig, (8, 0, b"x", 16))
        self.assertEqual(unknown[1], tool.PANIC_NAME)
        self.assertNotIn(("free", tool.INPUT, 16, 0), unknown[2])

    def test_end_check_accepts_exactly_the_four_ascii_bytes(self):
        for byte in range(256):
            observed = self.same(tool.real_endcheck, tool.spec_endcheck, (b"x" + bytes([byte]), 1, OK_DOCUMENT))
            self.assertEqual(observed[1] == 0, byte in (9, 10, 13, 32), byte)

    def test_end_check_starts_at_the_position_the_reader_left(self):
        for moved, tag in ((0, 1), (1, 1), (2, 1), (3, 0), (9, 0)):
            observed = self.same(tool.real_endcheck, tool.spec_endcheck, (b"x x", 0, (0, 1, moved, 0, None)))
            self.assertEqual(observed[1], tag, moved)
        failed = tool.real_endcheck(self.rig, (b"x x", 0, (0, 1, 1, 0, None)))
        self.assertEqual(failed[3][-1], ("error_new", 0x16))

    def test_end_check_frees_the_reader_scratch(self):
        observed = self.same(tool.real_endcheck, tool.spec_endcheck, (b"{}", 0, (1, 0, None, 0x3001, (16, 0x999))))
        self.assertEqual(observed[3], (("document",), ("free", 0x999, 16, 0)))
        observed = self.same(tool.real_endcheck, tool.spec_endcheck, (b"{}", 0, (1, 0, None, 0x3001, (0, 0x999))))
        self.assertEqual(observed[3], (("document",),))

    def test_quoted_reader_branches(self):
        spec = self.spec
        lead = b" \n\t\r"
        text = lead + b'"NvTestnet"'
        for case in ((text, 0, (0, tool.INPUT + 5, 9, len(text))), (text, 2, (0, tool.INPUT + 5, 9, len(text))),
                     (b"", 0, (0, 0, 0, None)), (b"  ", 0, (0, 0, 0, None)), (b"x", 0, (0, 0, 0, None)),
                     (b"\x0b\"Ec\"", 0, (0, tool.INPUT + 2, 2, 5)), (b'"ab', 0, (2, 0x4242, 0, None))):
            self.same(tool.real_quoted, lambda c: tool.spec_quoted(spec, c), case)
        good = tool.real_quoted(self.rig, (text, 0, (0, tool.INPUT + 5, 9, len(text))))
        self.assertEqual(good[1:5], (33, tool.READER, len(text), 0))
        eof = tool.real_quoted(self.rig, (b"  ", 0, (0, 0, 0, None)))
        self.assertEqual((eof[1], eof[5]), (tool.UNKNOWN, (("error_new", 5),)))
        other = tool.real_quoted(self.rig, (b" x", 0, (0, 0, 0, None)))
        self.assertEqual(other[3], 1)
        self.assertEqual(other[4], tool.SCRUB)

    def test_static_reader_branches(self):
        for case, expected in (
                ((b"{}", 24, (0x40, 0), (0, 7, 2, 0, None), None), 7),
                ((b"{}", 0, (0, 0), (0, 79, 2, 0, None), None), 79),
                ((b"{}  \n", 0, (0, 0), (0, 5, 2, 0, None), None), 5),
                ((b"{} x", 0, (0, 0), (0, 5, 2, 0, None), None), 33),
                ((b"{}\x0b", 0, (0, 0), (0, 5, 2, 0, None), None), 33),
                ((b"{}", 0, (S, 0x31), (0, 0, 0, 0, None), None), 33),
                ((b"{}", 8, (0, 0), (1, 0, None, 0, None), (0, 0x2222, 0x20)), 33),
                ((b"{}", 8, (0, 0), (1, 0, None, 0, None), (1, 0x3333, 0)), 33)):
            observed = self.same(tool.real_static, tool.spec_static, case)
            self.assertEqual(observed[1], expected, case)

    def test_static_reader_event_orders(self):
        read_error = tool.real_static(self.rig, (b"{}", 24, (S, 0x31), (0, 0, 0, 0, None), None))
        self.assertEqual(read_error[2], (("format", tool.FORMAT_ENTRY), ("read", tool.PATH_AT, 15), ("drop_io", 0x31),
                                         ("free", tool.PATH_AT, 24, 0)))
        boxed = tool.real_static(self.rig, (b"{}", 8, (16, 0), (1, 0, None, 0, None), (0, 0x2222, 0x20)))
        self.assertEqual(boxed[2][-4:], (("free", 0x2222, 0x20, 0), ("free", tool.BOX_AT + 0x100, 0x28, 0),
                                         ("free", tool.INPUT, 16, 0), ("free", tool.PATH_AT, 8, 0)))

    def test_every_family_agrees(self):
        rig, counts, outcomes, rows, bad = tool.analyse(self.image, self.spec, self.names, 8, tool.ROWS_EVERY)
        self.assertEqual(bad, [])
        self.assertGreater(sum(counts.values()), 30000)
        for key in ("plain", "serde", "trim", "missing", "endcheck", "quoted", "static"):
            self.assertGreater(counts[key], 250, key)
        for pair in (("missing", "panic read error"), ("missing", "panic unknown name"), ("endcheck", "trailing characters"),
                     ("quoted", "not a string"), ("quoted", "end of input"), ("static", "read error"), ("static", "document error"),
                     ("static", "trailing characters")):
            self.assertIn(pair, outcomes)

    # -- negative controls --
    def test_code_mutants_are_detected(self):
        mutants = tool.build_mutants(self.image, 12)
        picked = [m for m in mutants if m[0] in ("plain", "serde", "trim", "missing", "endcheck", "quoted", "static")][::7]
        self.assertGreater(len(picked), 8)
        cache = {}
        for key, description, patches, overlay in picked:
            site = tool.owner_instruction(self.image, cache, patches) if patches else None
            if site is not None and site not in self.rig.machine.seen:
                continue
            result, how = tool.detect(self.image, self.spec, self.names, key, patches, overlay, 8)
            self.assertEqual(result, "detected", (description, how))

    def test_a_return_immediate_flip_is_caught_by_exactly_its_name(self):
        row = [r for r in tool.rows_of(self.image, tool.PLAIN) if r.op == "mov" and r.b[0] == "i" and r.b[1] == 33 and r.width == 1][0]
        rig = tool.Rig(self.image, tool.imm_flip(self.image, row), {})
        wrong = [name for name in self.names if tool.real_plain(rig, name) != tool.spec_plain(self.spec, name)]
        self.assertEqual(wrong, [b"NvTestnet"])

    def test_jump_table_flip_is_caught(self):
        at = tool.JUMP_TABLES[tool.PLAIN] + 4 * 7
        rig = tool.Rig(self.image, {}, {at: self.image.blob[self.image.offset(at)] ^ 4})
        with self.assertRaises((tool.Halt, tool.EvidenceError, IndexError, ValueError)):
            for name in self.names:
                if tool.real_plain(rig, name) != tool.spec_plain(self.spec, name):
                    raise tool.EvidenceError("disagrees")

    def test_wrong_models_disagree(self):
        rows = tool.variants(self.image, self.spec, self.names, 8)
        self.assertGreaterEqual(len(rows), 24)
        for row in rows:
            self.assertGreater(row[3], 0, row)

    def test_corrupted_inputs_are_refused(self):
        controls = tool.corrupt_controls(self.image, self.spec, self.names)
        self.assertGreaterEqual(len(controls), 12)
        for label, ok in controls:
            self.assertTrue(ok, label)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_unmodelled_call_halts(self):
        rig = tool.Rig(self.image)
        rig.machine.slots = {}
        rig.load(b"Ec")
        with self.assertRaises(tool.Halt):
            rig.call(tool.MISSING, {})

    def test_read_window_and_guard_checks(self):
        rig = tool.Rig(self.image)
        rig.load(self.names[9])
        rig.call(tool.PLAIN, {tool.RDI: tool.INPUT, tool.RSI: len(self.names[9])})
        self.assertTrue(rig.reads_inside(tool.INPUT, tool.INPUT + len(self.names[9])))
        self.assertFalse(rig.reads_inside(tool.INPUT + 1, tool.INPUT + len(self.names[9])))
        rig.machine.memory.put_bytes(tool.INPUT + len(self.names[9]), b"\0")
        self.assertFalse(rig.guards_intact(self.names[9]))

    # -- committed evidence --
    def test_generated_tables_match_the_committed_files(self):
        self.assertEqual((FOLDER / "names.tsv").read_text(), "index\tname\tlength\tjump slot\tplain bucket\tplain steps\tplain return site\t"
                         "serde steps\tserde return site\n" + tool.table_text(tool.name_sites(self.image, self.spec, self.names)))
        self.assertEqual((FOLDER / "buckets.tsv").read_text(), "jump slot\tname length\tplain target\tserde target\tnames\tindices\n" +
                         tool.table_text(tool.bucket_rows(self.image, self.names)))
        self.assertEqual((FOLDER / "stubs.tsv").read_text(), "kind\tname\ttarget\tcontract\n" + tool.table_text(tool.STUB_ROLES))

    def test_generators_are_deterministic(self):
        def digest(items):
            return hashlib.sha256(repr(list(items)).encode()).hexdigest()
        self.assertEqual(digest(tool.name_inputs(self.names, 50)), digest(tool.name_inputs(self.names, 50)))
        self.assertEqual(digest(tool.static_inputs(self.names, 40)), digest(tool.static_inputs(self.names, 40)))
        self.assertEqual(digest(tool.quoted_inputs(self.names, 40)), digest(tool.quoted_inputs(self.names, 40)))

    def test_measure_and_manifest_are_consistent(self):
        measure = json.loads((FOLDER / "measure.json").read_text())
        evidence = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(measure["cases"], evidence["cases"])
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])
        self.assertEqual(measure["negative_controls"], evidence["mutants_detected"] + evidence["wrong_models"] + evidence["controls"])
        self.assertEqual(evidence["controls"], evidence["controls_detected"])
        self.assertEqual(evidence["wrong_models"], evidence["wrong_models_detected"])
        self.assertEqual(evidence["binary_sha256"], tool.SHA256)
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)



class NameFlowTables115(unittest.TestCase):
    """Per-spelling, per-value and per-file checks that complement the family comparisons above."""

    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.names = tool.read_names(cls.image, tool.NAME_ARRAYS[0])
        cls.spec = tool.Spec(cls.names)
        cls.rig = tool.Rig(cls.image)

    def rows(self, name):
        lines = (FOLDER / name).read_text().splitlines()
        return [line.split("\t") for line in lines[1:]]

    def test_slots_resolve_to_the_documented_targets(self):
        relative = tool.relative_map(self.image)
        expected = dict(free=0x635DE30, unwrap=0x1680C30, expect=0x1681DA0, resume=0x1680CAB, read=0x5CA4940, path=0x1772FA0, classify=tool.PLAIN, string=0x5C56B60)
        for name, target in expected.items():
            self.assertEqual(relative[tool.SLOTS[name]], target, name)
        self.assertEqual(relative[tool.WS_SLOT], tool.WS_TABLE)

    def test_every_spelling_through_the_quoted_reader(self):
        for index, name in enumerate(self.names):
            text = b' "' + name + b'"'
            observed = tool.real_quoted(self.rig, (text, 0, (0, tool.INPUT + 2, len(name), len(text))))
            self.assertEqual(observed[1], index, name)
            self.assertEqual(observed[5], (("string", tool.READER),))
            self.assertEqual(observed[3], len(text))

    def test_every_spelling_through_the_missing_name_reader(self):
        for index, name in enumerate(self.names):
            for pad in tool.PAD:
                observed = tool.real_missing(self.rig, (0, 0, pad + name + pad, 0))
                self.assertEqual(observed[:2], ("ret", index), (name, pad))

    def test_every_document_value_through_the_static_reader(self):
        for value in range(256):
            observed = tool.real_static(self.rig, (b"{}\n", 0, (0, 0), (0, value, 2, 0, None), None))
            self.assertEqual(observed[1], value)
            observed = tool.real_static(self.rig, (b"{}x", 0, (0, 0), (0, value, 2, 0, None), None))
            self.assertEqual(observed[1], tool.DEFAULT_NAME)

    def test_serde_error_carries_the_length_for_every_length(self):
        for length in range(0, 41):
            observed = tool.real_serde(self.rig, bytes([0x61 + length % 7]) * length)
            if observed[1] == 1:
                self.assertEqual(observed[2], tool.ERROR_BASE + length)
                self.assertEqual(observed[3], (("unknown_variant", tool.INPUT, length, tool.NAME_ARRAYS[1], 79),))

    def test_trim_against_an_independent_regular_expression(self):
        import re
        pattern = re.compile("[\t-\r \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*")
        rng = tool.Lcg(0xABC)
        for _ in range(1500):
            text = "".join(tool.CHAR_POOL[rng.below(len(tool.CHAR_POOL))] for _ in range(rng.below(9)))
            data = text.encode()
            observed = tool.real_trim(self.rig, data)
            lead = pattern.match(text).end()
            body = text[lead:]
            end = len(body)
            while end and pattern.fullmatch(body[end - 1]):
                end -= 1
            trimmed = body[:end]
            start = len(text[:lead].encode()) if trimmed else 0
            self.assertEqual(observed[1:3], (start, len(trimmed.encode())), repr(text))

    def test_names_table_has_unique_return_sites_inside_the_functions(self):
        rows = self.rows("names.tsv")
        self.assertEqual(len(rows), 79)
        plain = {row[6] for row in rows}
        serde = {row[8] for row in rows}
        self.assertEqual(len(plain), 79)
        self.assertEqual(len(serde), 79)
        for row in rows:
            self.assertEqual(self.names[int(row[0])].decode(), row[1])
            self.assertGreater(int(row[5]), 5)
            self.assertTrue(tool.PLAIN <= int(row[6], 16) < tool.PLAIN + 0x900)
            self.assertTrue(tool.SERDE <= int(row[8], 16) < tool.SERDE + 0xB00)

    def test_outcomes_sum_to_the_case_count(self):
        evidence = json.loads((FOLDER / "evidence.json").read_text())
        rows = self.rows("outcomes.tsv")
        self.assertEqual(sum(int(row[2]) for row in rows), evidence["cases"])
        per_family = {}
        for family, _, count in rows:
            per_family[family] = per_family.get(family, 0) + int(count)
        self.assertEqual(per_family, evidence["per_family"])

    def test_unstepped_instructions_are_few_and_listed(self):
        for name, start, end, instructions, stepped, dark in self.rows("coverage.tsv"):
            self.assertLessEqual(int(instructions) - int(stepped), 25, name)
            self.assertEqual(bool(dark), int(instructions) != int(stepped), name)
        evidence = json.loads((FOLDER / "evidence.json").read_text())
        results = [row[2] for row in self.rows("mutants.tsv")]
        self.assertEqual(results.count("detected"), evidence["mutants_detected"])
        self.assertEqual(results.count("not stepped"), evidence["mutants_not_stepped"])
        self.assertEqual(results.count("survived"), evidence["mutants_survived"])

    def test_cases_sample_names_only_known_families_and_outcomes(self):
        outcomes = {(row[0], row[1]) for row in self.rows("outcomes.tsv")}
        sampled = self.rows("cases.tsv")
        self.assertGreater(len(sampled), 2000)
        for family, number, outcome, shown, result in sampled:
            self.assertIn((family, outcome), outcomes)
            self.assertTrue(number.isdigit())

    def test_variants_and_controls_files_report_only_detections(self):
        for row in self.rows("variants.tsv"):
            self.assertGreater(int(row[3]), 0, row)
            self.assertLessEqual(int(row[3]), int(row[4]))
        for row in self.rows("controls.tsv"):
            self.assertEqual(row[1], "True", row)


if __name__ == "__main__":
    unittest.main()
