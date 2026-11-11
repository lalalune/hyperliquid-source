import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vault_serializers_115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "vaults-struct-serializers-115"


def canonical(entry, flag):
    return [case for case in tool.canonical_cases() if case.entry == entry and case.flag == flag][0]


def with_obj(case, obj):
    return tool.with_obj(case, obj)


def with_changes(case, **changes):
    fields = {name: getattr(case, name) for name in tool.Case.__slots__}
    fields.update(changes)
    return tool.Case(**fields)


class VaultSerializerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def agree(self, case, variant=frozenset()):
        got = self.harness.run(case)
        return tool.compare(got, tool.model(self.image, case, variant)), got

    def test_digest_is_checked_first(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "hl-node"
            path.write_bytes(b"\x7fELF" + bytes(100))
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_binary_digest_constant(self):
        self.assertEqual(tool.base.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), tool.base.SHA256)

    def test_function_extents(self):
        self.assertEqual(self.image.exact_fde(tool.TAGGED), (0x44A66F0, 0x44A6A20))
        self.assertEqual(self.image.exact_fde(tool.PACKED), (0x44A6A20, 0x44A6EAD))

    def test_interior_and_outside_addresses_are_refused(self):
        for va in (tool.TAGGED + 1, tool.PACKED - 1, tool.PACKED + 0x1000000, 0x7FFFFFFFFF):
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(va)

    def test_callee_tables_are_the_call_sets_of_the_bytes(self):
        tool.verify_tables(self.image)
        saved = dict(tool.TAGGED_CALLS)
        try:
            del tool.TAGGED_CALLS[0x44FC0B0]
            with self.assertRaises(tool.EvidenceError):
                tool.verify_tables(self.image)
        finally:
            tool.TAGGED_CALLS.clear()
            tool.TAGGED_CALLS.update(saved)

    def test_key_texts_come_from_the_bytes(self):
        for label in tool.KEYS:
            self.assertEqual(tool.key_bytes(self.image, label), label.encode())
        saved = tool.KEYS["name"]
        try:
            tool.KEYS["name"] = (saved[0] + 1, saved[1])
            with self.assertRaises(tool.EvidenceError):
                tool.key_bytes(self.image, "name")
        finally:
            tool.KEYS["name"] = saved

    def test_canonical_cases_match_the_rule_list(self):
        for case in tool.canonical_cases():
            self.assertIsNone(self.agree(case)[0], case.name)

    def test_packed_header_byte_for_each_flag_value(self):
        expected = {0: 0x9D, 1: 0x8D, 2: 0xBD, 0xFF: 0xED}
        for flag, header in expected.items():
            case = with_changes(canonical(tool.PACKED, 1), flag=flag)
            result, got = self.agree(case)
            self.assertIsNone(result)
            self.assertEqual(got["buf"][case.length], header)
            self.assertEqual(tool.packed_header(flag, frozenset()), header)

    def test_flag_two_is_not_the_named_form(self):
        for entry in tool.TARGETS:
            plain = self.harness.run(with_changes(canonical(entry, 1), flag=2))["log"]
            named = self.harness.run(canonical(entry, 1))["log"]
            self.assertEqual(sum(1 for item in plain if item[0] == "write_str"), 2)
            self.assertGreater(len(named), len(plain))

    def test_tagged_begin_selection(self):
        zero = self.harness.run(canonical(tool.TAGGED, 0))["log"][0]
        one = self.harness.run(canonical(tool.TAGGED, 1))["log"][0]
        self.assertEqual((zero[0], one[0]), ("begin_b", "begin_a"))
        self.assertEqual(zero[2], 0xD)

    def test_named_form_writes_inline_keys(self):
        case = canonical(tool.PACKED, 1)
        got = self.harness.run(case)
        text = bytes(got["buf"][:got["length"]])
        self.assertEqual(text[:6], b"\x8d\xa4name")
        self.assertIn(b"\xabdescription", text)
        self.assertIn(b"\xabcreate_time", text)
        compact = self.harness.run(canonical(tool.PACKED, 0))
        self.assertEqual(compact["length"], 1)

    def test_room_tests_ask_for_growth_exactly_when_short(self):
        case = canonical(tool.PACKED, 1)
        for spare in range(0, 16):
            probe = with_changes(case, cap=spare, length=0)
            result, got = self.agree(probe)
            self.assertIsNone(result, spare)
        first = self.harness.run(with_changes(case, cap=0, length=0))["log"][0]
        self.assertEqual(first, ("reserve", "ser", 0, 1, 1, 1))
        roomy = self.harness.run(with_changes(case, cap=0x300, length=0))["log"]
        self.assertFalse(any(item[0] == "reserve" for item in roomy))
        tight = self.harness.run(with_changes(case, cap=5, length=0))["log"]
        self.assertEqual([item[3] for item in tight if item[0] == "reserve"][:1], [4])

    def test_growth_formula_is_the_stub_contract(self):
        got = self.harness.run(with_changes(canonical(tool.PACKED, 1), cap=0, length=0))
        self.assertEqual(got["log"][0], ("reserve", "ser", 0, 1, 1, 1))
        self.assertEqual(got["cap"] >= got["length"], True)

    def test_result_record_shapes(self):
        marker = (0x1111111111111111, 0x2222222222222222, 0x3333333333333333)
        for entry in tool.TARGETS:
            base_case = canonical(entry, 1)
            calls = [item for item in self.harness.run(base_case)["log"] if item[0] != "reserve"]
            for index, item in enumerate(calls):
                case = with_changes(base_case, fail_at=index, fail=marker)
                result, got = self.agree(case)
                self.assertIsNone(result, (entry, index))
                words = struct.unpack("<QQQ", got["out"])
                kind = tool.ALL_CALLS[[a for a, v in tool.ALL_CALLS.items() if v[0] == item[0] and (a in tool.ENTRY_CALLS[entry])][0]][1]
                if kind == "rec":
                    self.assertEqual(words, marker)
                else:
                    self.assertEqual(words[0], tool.ERR_TAG)
                    self.assertEqual(words[1], marker[0])

    def test_success_leaves_only_the_tag_word(self):
        for entry in tool.TARGETS:
            got = self.harness.run(canonical(entry, 1))
            self.assertEqual(got["out"][:8], struct.pack("<Q", tool.OK_TAG))
            self.assertEqual(got["out"][8:], tool.pattern(tool.OUT_SIZE, 0x60)[8:])

    def test_error_code_two_is_never_returned_as_failure(self):
        case = with_changes(canonical(tool.PACKED, 1), fail_at=1, fail=(2, 5, 6))
        result, got = self.agree(case)
        self.assertIsNone(result)
        self.assertEqual(struct.unpack("<QQQ", got["out"])[1], 3)

    def test_random_cases_agree(self):
        count = 0
        for case in tool.vector_cases(1200, seed=0xFEED):
            self.assertIsNone(self.agree(case)[0], case.name)
            count += 1
        self.assertEqual(count, 1200)

    def test_every_rule_list_mutant_is_refused(self):
        pool = [case for _, case in zip(range(900), tool.vector_cases(900, seed=0x51ED))]
        rows = tool.negative_rows(self.image, pool)
        self.assertEqual(len(rows), len(tool.MODEL_MUTANTS) + len(tool.CODE_PATCHES) + 5 + 3)
        for row in rows:
            self.assertEqual(row[2], 1, row)

    def test_a_correct_rule_list_is_not_refused(self):
        for case in tool.vector_cases(300, seed=0xABCD):
            self.assertIsNone(self.agree(case)[0])

    def test_patch_sites_hold_the_expected_original_bytes(self):
        for address, old, new, label in tool.CODE_PATCHES:
            start = self.image.offset(address)
            self.assertEqual(bytes(self.image.blob[start:start + len(old)]), old, label)
            self.assertNotEqual(old, new)

    def test_wrong_patch_expectation_is_an_error(self):
        saved = tool.CODE_PATCHES
        tool.CODE_PATCHES = ((0x44A686B, b"\x00", b"\x01", "bad expectation"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.negative_rows(self.image, [next(tool.vector_cases(1))])
        finally:
            tool.CODE_PATCHES = saved

    def test_corrupted_code_byte_changes_behaviour(self):
        patched = tool.Harness(self.image, {0x44A686B: 0x90})
        case = canonical(tool.TAGGED, 1)
        self.assertNotEqual(patched.run(case)["log"], self.harness.run(case)["log"])

    def test_unmodelled_callee_halts(self):
        dropped = tool.Harness(self.image, drop=0x44FB6F0)
        with self.assertRaises(tool.Halt):
            dropped.run(canonical(tool.TAGGED, 1))

    def test_unrelated_heap_is_untouched(self):
        for entry in tool.TARGETS:
            got = self.harness.run(canonical(entry, 1))
            self.assertEqual(len(got["buf"]), tool.BUF_SIZE)

    def prefix_case(self, entry, flag, value, fail_at=None):
        obj = struct.pack("<Q", value) + bytes(tool.OBJ_SIZE - 8)
        return tool.Case("prefix", entry, obj, bytes(tool.STRS_SIZE), flag, 0, 0, fail_at, (7, 9, 11))

    def test_prefix_f64_writer_without_flag_goes_straight_to_the_tail(self):
        case = self.prefix_case(tool.PREFIX_F64, 0, 0x4009000000000000)
        got = tool.prefix_run(self.harness, case)
        self.assertEqual(got["log"], [("tail_f64", "ser", 0x4009000000000000)])
        self.assertEqual(struct.unpack("<QQQ", got["out"]), tool.TAIL_MARK)

    def test_prefix_f64_writer_with_flag_writes_the_key_first(self):
        case = self.prefix_case(tool.PREFIX_F64, 1, 0x3FF0000000000000)
        got = tool.prefix_run(self.harness, case)
        self.assertEqual(got["log"][0], ("write_str", "ser", ("S", b"leader_commission")))
        self.assertEqual(got["log"][1], ("tail_f64", "ser", 0x3FF0000000000000))
        self.assertIsNone(tool.compare(got, tool.prefix_model(self.image, case)))

    def test_prefix_failure_returns_the_error_record_and_skips_the_tail(self):
        for entry in tool.PREFIXES:
            case = self.prefix_case(entry, 1, 5, fail_at=0)
            got = tool.prefix_run(self.harness, case)
            self.assertEqual(len(got["log"]), 1)
            self.assertEqual(struct.unpack("<QQQ", got["out"]), (tool.ERR_TAG, 7, 9))

    def test_prefix_word_writer_key_and_value_order(self):
        case = self.prefix_case(tool.PREFIX_WORD, 3, 0x1234)
        got = tool.prefix_run(self.harness, case)
        self.assertEqual(got["log"], [("write_str", "ser", ("S", b"sub_deployers")), ("tail_value", 0x1234, "ser")])

    def test_prefix_tail_targets_are_checked_from_the_bytes(self):
        tool.verify_prefix_tables(self.image)
        saved = tool.PREFIX_CALLS
        tool.PREFIX_CALLS = {}
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.verify_prefix_tables(self.image)
        finally:
            tool.PREFIX_CALLS = saved

    def test_record_bytes_seen_by_the_serializers(self):
        rows = tool.influence_rows(self.image, self.harness)
        seen = {}
        for case, offset, indices, callees in rows:
            seen.setdefault(case, set()).add(int(offset, 16))
        self.assertEqual(len(seen), 4)
        expected = {0x28, 0x30, 0x40, 0x48} | set(range(0x70, 0x80)) | {0xB4, 0xB5, 0xB6, 0xB7}
        for case, offsets in seen.items():
            self.assertEqual(offsets, expected, case)
        for row in rows:
            if row[1] == "0xb5":
                self.assertEqual(len(row[3].split()), 2)

    def test_pointer_only_fields_are_not_read_by_the_writers(self):
        for entry in tool.TARGETS:
            case = canonical(entry, 1)
            obj = bytearray(case.obj)
            for offset in list(range(0x80, 0xB4)) + list(range(0, 0x28)):
                obj[offset] ^= 0xFF
            self.assertEqual(self.harness.run(with_obj(case, bytes(obj)))["log"], self.harness.run(case)["log"])

    def test_generated_evidence_is_current(self):
        result = tool.analyse(self.image)
        self.assertEqual(result["mismatches"], 0)
        files = tool.render(result)
        measure = json.loads(files["measure.json"])
        self.assertEqual(measure["negative_detected"], measure["negative_controls"])
        self.assertGreaterEqual(measure["cases"], 10000)
        self.assertGreaterEqual(measure["negative_controls"], 30)
        if WORK.exists():
            for name, text in files.items():
                self.assertEqual((WORK / name).read_text(encoding="ascii"), text, name)


if __name__ == "__main__":
    unittest.main()
