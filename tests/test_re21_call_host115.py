"""Tests for the selected node-115 CALL-family static evidence packet."""
import json
from pathlib import Path
import struct
import unittest
from unittest import mock

from tools import re21_call_host115 as packet


WORK_ITEM = packet.ROOT / "research/work-items/RE-021-call-host-115"


def section(name, address, offset, size, section_type=1, flags=4):
    return {"name": name, "address": address, "offset": offset, "size": size,
            "type": section_type, "flags": flags}


class TargetEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        cls.secs = packet.sections(cls.data)
        cls.generated = packet.analyze(cls.data)

    def test_digest_of_real_target(self):
        self.assertEqual(packet.authenticate(self.data), packet.TARGET_SHA)

    def test_bad_target_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            packet.authenticate(b"not the captured node")

    def test_saved_evidence_equals_regenerated_bytes(self):
        for name, expected in self.generated.items():
            with self.subTest(name=name):
                self.assertEqual((WORK_ITEM / name).read_bytes(), expected)

    def test_expected_scope_and_extents(self):
        records = json.loads(self.generated["functions.json"])
        self.assertEqual(len(records), 12)
        self.assertEqual(sum(x["size"] for x in records), 11655)
        self.assertEqual(records[0]["start_va"], "0x22d9070")
        self.assertEqual(records[0]["end_va_exclusive"], "0x22d949c")
        self.assertEqual(len({x["fde_va"] for x in records}), len(records))
        for row in records:
            self.assertEqual(len(bytes.fromhex(row["body_bytes"])), row["size"])

    def test_pair_masks_and_host_are_explicit(self):
        pairs = json.loads(self.generated["paired-bodies.json"])
        self.assertEqual(len(pairs), 3)
        for pair in pairs:
            with self.subTest(pair=pair["variant"]):
                self.assertEqual(pair["raw_different_byte_positions"], 24)
                self.assertEqual(pair["masked_byte_positions"], 48)
                self.assertEqual(len(pair["operands"]), 12)
                differing = [x for x in pair["operands"]
                             if x["ordinary_target_va"] != x["alternate_target_va"]]
                self.assertEqual(len(differing), 1)
                self.assertEqual((differing[0]["ordinary_target_va"], differing[0]["alternate_target_va"]),
                                 ("0x64e6e00", "0x64e6e08"))

    def test_saved_frame_modes(self):
        rows = packet.frame_rows(self.data, self.secs)
        self.assertEqual(len(rows), 7)
        expected = {0xf1: (0, 0), 0xf2: (0, 1), 0xf4: (1, 2), 0xfa: (0, 3)}
        for row in rows:
            self.assertEqual(row[5], 208)
            self.assertEqual((row[8], row[12]), expected[int(row[1], 16)])
            self.assertEqual(row[11], "0xce")
            self.assertEqual(row[19], 1 if int(row[1], 16) == 0xf1 else 0)

    def test_handler_gates_and_revision_checks(self):
        rows = {row[0]: row for row in packet.handler_gate_rows(self.data, self.secs)}
        self.assertEqual(len(rows), 7)
        for name in ("ordinary_delegate", "alternate_delegate"):
            self.assertEqual((rows[name][4], rows[name][5], rows[name][14]), (2, "0x2c", "eq:0"))
        for name in ("ordinary_static", "alternate_static"):
            self.assertEqual((rows[name][4], rows[name][14]), (2, "unsigned_le:3"))
        for name in ("ordinary_callcode", "alternate_callcode", "alternate_call"):
            self.assertEqual(rows[name][4], 3)
        self.assertEqual(rows["alternate_call"][17], "0x299a99f")

    def test_classifier_pair_shares_literals(self):
        pair = json.loads(self.generated["classification-pair.json"])
        self.assertTrue(pair["unmasked_bytes_equal"])
        self.assertEqual(pair["size_each"], 145)
        self.assertEqual(len(pair["masked_byte_positions"]), 9)
        self.assertEqual([x["target_va"] for x in pair["references"]], ["0x452020", "0x4537f0"])

    def test_classifier_pair_rejects_modified_unmasked_byte(self):
        a, b, size = 0x546c42f, 0x546c720, 0x91
        first = packet.read_va(self.data, self.secs, a, size)[0]
        second = packet.read_va(self.data, self.secs, b, size)[0]
        data = bytearray(first + second)
        data[0] ^= 1
        secs = [section("a", a, 0, size), section("b", b, size, size)]
        with self.assertRaisesRegex(ValueError, "outside checked fields"):
            packet.classification_pair(data, secs)

    def test_address_09_records_and_distinct_callbacks(self):
        constants = json.loads(self.generated["constants.json"])
        self.assertEqual(constants["address09_ordinary"]["bytes"], "00" * 19 + "09")
        self.assertEqual(constants["address09_ordinary"]["bytes"], constants["address09_scaled"]["bytes"])
        self.assertEqual(constants["address09_scaled"]["divisor"], 10)
        relocations = packet.relative_relocations(self.data, self.secs, {0x64c0748, 0x6493010})
        self.assertEqual(relocations[0x64c0748]["addend"], 0x5c165b0)
        self.assertEqual(relocations[0x6493010]["addend"], 0x5c16650)

    def test_driver_copy_symbol_is_undefined_memcpy(self):
        sym = packet.symbol_relocation(self.data, self.secs, 0x64df508)
        self.assertEqual((sym["name"], sym["relocation_type"], sym["symbol_section_index"]),
                         ("memcpy", 6, 0))
        self.assertEqual(sym["addend"], 0)

    def test_selected_exception_coverage(self):
        rows = self.generated["exceptions.tsv"].decode().splitlines()
        self.assertTrue(any("alternate_delegate\t" in r and "0x299a800\t0x299a856\t0x299a8a8" in r for r in rows))
        self.assertTrue(any("alternate_host\t" in r and "0x546c718\t0x546c720\t0x546cb6f" in r for r in rows))

    def _pair_fixture(self):
        pair = packet.PAIRS[0]
        ends = {start: end for _, start, end in packet.FUNCTIONS}
        _, a, b, _, _ = pair
        left = packet.read_va(self.data, self.secs, a, ends[a] - a)[0]
        right = packet.read_va(self.data, self.secs, b, ends[b] - b)[0]
        secs = [section("left", a, 0, len(left)), section("right", b, len(left), len(right))]
        return bytearray(left + right), secs, pair, ends, len(left)

    def test_mutated_pair_body_rejected(self):
        data, secs, pair, ends, _ = self._pair_fixture()
        data[1] ^= 1
        with self.assertRaisesRegex(ValueError, "non-operand"):
            packet.compare_pair(data, secs, *pair, ends)

    def test_mutated_masked_target_rejected(self):
        data, secs, pair, ends, _ = self._pair_fixture()
        data[pair[3][0]] ^= 1
        with self.assertRaisesRegex(ValueError, "target differs"):
            packet.compare_pair(data, secs, *pair, ends)

    def test_frame_scheme_corruption_rejected(self):
        spec = packet.FRAME_MODES[0]
        _, _, _, copy_va, tag_va, scheme_va, key_va, action_va = spec
        pieces = [(copy_va, 10), (tag_va, 9), (scheme_va, 8), (key_va, 24), (action_va, 31)]
        blob = bytearray()
        secs = []
        for va, size in pieces:
            raw = packet.read_va(self.data, self.secs, va, size)[0]
            secs.append(section("part", va, len(blob), size))
            blob.extend(raw)
        blob[secs[2]["offset"] + 7] ^= 1
        with mock.patch.object(packet, "FRAME_MODES", (spec,)):
            with self.assertRaisesRegex(ValueError, "scheme offset or value"):
                packet.frame_rows(blob, secs)

    def test_handler_gate_rejects_changed_comparison(self):
        spec = packet.HANDLER_GATES[0]
        _, stack, range_call, alloc, revision, _ = spec
        rev_target = packet.decode_edge(self.data, self.secs, revision + 7, "jcc")[3]
        pieces = [(stack, 6), (stack + 6, 6), (range_call, 5), (alloc, 6),
                  (revision, 7), (revision + 7, 6), (rev_target, 2)]
        blob = bytearray()
        secs = []
        for va, size in pieces:
            raw = packet.read_va(self.data, self.secs, va, size)[0]
            secs.append(section("part", va, len(blob), size))
            blob.extend(raw)
        blob[secs[1]["offset"] + 1] = 0x8f
        with mock.patch.object(packet, "HANDLER_GATES", (spec,)):
            with self.assertRaisesRegex(ValueError, "stack predicate"):
                packet.handler_gate_rows(blob, secs)


class ParsingControls(unittest.TestCase):
    @staticmethod
    def symbol_fixture():
        blob = bytearray(88)
        struct.pack_into("<QQq", blob, 0, 0x2000, (1 << 32) | 6, 0)
        struct.pack_into("<IBBHQQ", blob, 48, 1, 0x12, 0, 0, 0, 0)
        blob[72:80] = b"\0memcpy\0"
        secs = [section(".rela.dyn", 0, 0, 24, 4, 2),
                section(".dynsym", 0x100, 24, 48, 11, 2),
                section(".dynstr", 0x200, 72, 8, 3, 2),
                section(".got", 0x2000, 80, 8, 1, 3)]
        return blob, secs

    def test_file_mapping_excludes_nobits(self):
        secs = [section(".bss", 0x1000, 0, 16, 8, 3)]
        with self.assertRaisesRegex(ValueError, "file-backed"):
            packet.mapping(secs, 0x1000, 1)

    def test_mapping_rejects_overlap_and_crossing(self):
        secs = [section("a", 0x1000, 0, 8), section("b", 0x1000, 8, 8)]
        with self.assertRaisesRegex(ValueError, "one file-backed"):
            packet.mapping(secs, 0x1000, 1)
        with self.assertRaisesRegex(ValueError, "file-backed"):
            packet.mapping(secs[:1], 0x1007, 2)

    def test_mapping_rejects_non_executable_and_truncated(self):
        secs = [section("data", 0x1000, 0, 8, 1, 2)]
        with self.assertRaises(ValueError):
            packet.read_va(b"12345678", secs, 0x1000, 1, executable=True)
        with self.assertRaisesRegex(ValueError, "exceeds input"):
            packet.read_va(b"123", secs, 0x1000, 4)
        for bad_length in (0, -1):
            with self.assertRaises(ValueError):
                packet.mapping(secs, 0x1000, bad_length)

    def test_exact_window_accepts_then_rejects_corruption(self):
        expected = bytes.fromhex("4883f902")
        secs = [section(".text", 0x1000, 0, 4)]
        pins = (("test", 0x1000, expected.hex()),)
        self.assertEqual(packet.assert_pins(expected, secs, pins)[0][1], "0x1000")
        with self.assertRaisesRegex(ValueError, "window changed"):
            packet.assert_pins(expected[:-1] + b"\x03", secs, pins)

    def test_relative_branch_decode_and_bad_opcode(self):
        sec = [section(".text", 0x1000, 0, 2)]
        self.assertEqual(packet.decode_edge(b"\x74\x05", sec, 0x1000, "jcc")[3], 0x1007)
        self.assertEqual(packet.decode_edge(b"\x74\xfd", sec, 0x1000, "jcc")[3], 0x0fff)
        with self.assertRaisesRegex(ValueError, "opcode"):
            packet.decode_edge(b"\x90\x90", sec, 0x1000, "jcc")

    def test_changed_branch_target_rejected(self):
        sec = [section(".text", 0x1000, 0, 2)]
        with mock.patch.object(packet, "EDGES", (("edge", 0x1000, "jcc", 0x1007),)):
            with self.assertRaisesRegex(ValueError, "target changed"):
                packet.edge_rows(b"\x74\x04", sec)

    def test_relative_relocation_missing_duplicate_and_wrong_type(self):
        good = struct.pack("<QQq", 0x2000, 8, 0x3000)
        one = [section(".rela.dyn", 0, 0, 24, 4, 0)]
        self.assertEqual(packet.relative_relocations(good, one, {0x2000})[0x2000]["addend"], 0x3000)
        with self.assertRaisesRegex(ValueError, "missing"):
            packet.relative_relocations(good, one, {0x2001})
        with self.assertRaisesRegex(ValueError, "non-relative"):
            packet.relative_relocations(struct.pack("<QQq", 0x2000, 7, 0x3000), one, {0x2000})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            packet.relative_relocations(good + good, [section(".rela.dyn", 0, 0, 48, 4, 0)], {0x2000})

    def test_dynamic_symbol_index_and_name_corruption(self):
        data, secs = self.symbol_fixture()
        self.assertEqual(packet.symbol_relocation(data, secs, 0x2000)["name"], "memcpy")
        struct.pack_into("<Q", data, 8, (2 << 32) | 6)
        with self.assertRaisesRegex(ValueError, "symbol relocation"):
            packet.symbol_relocation(data, secs, 0x2000)
        data, secs = self.symbol_fixture()
        data[79] = ord("x")
        with self.assertRaisesRegex(ValueError, "unterminated"):
            packet.symbol_relocation(data, secs, 0x2000)

    def test_exception_table_valid_and_outside_fde(self):
        data = bytes.fromhex("ffff010400010200")
        sec = [section(".gcc_except_table", 0x2000, 0, len(data))]
        fde = {"label": "x", "lsda": 0x2000, "start": 0x100, "end": 0x110}
        header, rows = packet.decode_lsda(data, sec, fde)
        self.assertEqual(header["callsite_bytes"], 4)
        self.assertEqual(rows[0][3:6], ("0x100", "0x101", "0x102"))
        with self.assertRaisesRegex(ValueError, "outside selected FDE"):
            packet.decode_lsda(bytes.fromhex("ffff010420010200"), sec, fde)

    def test_exception_table_rejects_bad_header_and_truncation(self):
        fde = {"label": "x", "lsda": 0x2000, "start": 0x100, "end": 0x110}
        bad = bytes.fromhex("00ff010400010200")
        with self.assertRaisesRegex(ValueError, "header"):
            packet.decode_lsda(bad, [section(".gcc_except_table", 0x2000, 0, len(bad))], fde)
        truncated = bytes.fromhex("ffff01040001")
        with self.assertRaisesRegex(ValueError, "crosses section"):
            packet.decode_lsda(truncated, [section(".gcc_except_table", 0x2000, 0, len(truncated))], fde)

    def test_legacy_hash_control_does_not_require_legacy_artifact(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            packet.check_legacy(b"wrong historical input")


class SyntheticControls(unittest.TestCase):
    EMPTY_HASH = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_each_of_256_stack_bits_projects_as_expected(self):
        for bit in range(256):
            with self.subTest(bit=bit):
                expected = (1 << bit).to_bytes(32, "big")[12:]
                self.assertEqual(packet.project_key(1 << bit), expected)

    def test_address_nine_and_ignored_high_bits(self):
        nine = bytes(19) + b"\x09"
        self.assertEqual(packet.project_key(9), nine)
        self.assertEqual(packet.project_key((1 << 255) | 9), nine)
        self.assertNotEqual(packet.project_key(8), nine)
        self.assertNotEqual(packet.project_key(10), nine)

    def test_stack_word_range(self):
        for value in (-1, 1 << 256, "9", True):
            with self.assertRaises(ValueError):
                packet.project_key(value)

    def test_base_charge_boundary_and_wrap(self):
        self.assertEqual(packet.base_charge(0, 0), (0, True))
        self.assertEqual(packet.base_charge(5, 5), (0, True))
        self.assertEqual(packet.base_charge(4, 5), ((1 << 64) - 1, False))
        self.assertEqual(packet.base_charge(10, 3), (7, True))
        for args in ((-1, 0), (1 << 64, 0), (0, 1 << 16)):
            with self.assertRaises(ValueError):
                packet.base_charge(*args)

    def test_classifier_low_mode_flags(self):
        classify = packet.account_classification
        zero = bytes(32)
        one = bytes(31) + b"\x01"
        self.assertTrue(classify(2, one, one, 1, 0x08, self.EMPTY_HASH))
        self.assertFalse(classify(2, zero, zero, 0, 0x0c, self.EMPTY_HASH))
        self.assertFalse(classify(2, zero, zero, 0, 0x00, self.EMPTY_HASH))
        self.assertTrue(classify(0, zero, zero, 0, 0xf9, self.EMPTY_HASH))

    def test_classifier_high_mode_fields_individually(self):
        classify = packet.account_classification
        zero = bytes(32)
        one = bytes(31) + b"\x01"
        self.assertTrue(classify(3, self.EMPTY_HASH, zero, 0, 0, self.EMPTY_HASH))
        self.assertTrue(classify(3, zero, zero, 0, 0xff, self.EMPTY_HASH))
        self.assertFalse(classify(3, one, zero, 0, 0, self.EMPTY_HASH))
        self.assertFalse(classify(3, self.EMPTY_HASH, one, 0, 0, self.EMPTY_HASH))
        self.assertFalse(classify(3, self.EMPTY_HASH, zero, 1, 0, self.EMPTY_HASH))
        for bit in range(256):
            word = (1 << bit).to_bytes(32, "big")
            self.assertFalse(classify(3, self.EMPTY_HASH, word, 0, 0, self.EMPTY_HASH))

    def test_classifier_rejects_bad_fields(self):
        zero = bytes(32)
        with self.assertRaisesRegex(ValueError, "32-byte"):
            packet.account_classification(3, b"bad", zero, 0, 0, self.EMPTY_HASH)
        with self.assertRaisesRegex(ValueError, "byte domain"):
            packet.account_classification(256, zero, zero, 0, 0, self.EMPTY_HASH)
        with self.assertRaisesRegex(ValueError, "64-bit"):
            packet.account_classification(3, zero, zero, -1, 0, self.EMPTY_HASH)

    def test_loader_policy_boolean_matrix(self):
        model = packet.loader_policy
        self.assertEqual(model(False, False), ("accept", True, True, 1))
        self.assertEqual(model(False, True), ("accept", False, True, 0))
        self.assertEqual(model(True, False), ("reject", False, False, None))
        self.assertEqual(model(True, True), ("accept", False, True, 0))
        with self.assertRaises(ValueError):
            model(1, False)

    def test_primary_cost_revision_and_mode_boundaries(self):
        cost = packet.primary_cost
        self.assertEqual(cost(6, 0, 1, False, False, False, 1000, 25000), (False, "ok", 0))
        self.assertEqual(cost(7, 999, 1, False, False, False, 1000, 25000), (True, "ok", 1000))
        self.assertEqual(cost(7, 1000, 1, False, False, False, 1000, 25000), (False, "ok", 1000))
        self.assertEqual(cost(2, 0, 0, True, True, False, 1000, 25000), (False, "ok", 25000))
        self.assertEqual(cost(3, 0, 0, True, True, False, 1000, 25000), (False, "ok", 0))
        self.assertEqual(cost(7, 0, 1, True, True, True, 1000, 25000), (True, "ok", 26000))
        self.assertEqual(cost(7, 0, 1, False, True, True, 1000, 25000), (True, "ok", 1000))

    def test_primary_cost_rejects_or_detects_overflow(self):
        cost = packet.primary_cost
        self.assertEqual(cost(7, 0, 2, True, True, True, 1000, 25000), (True, "loader_error", None))
        self.assertEqual(cost(7, 0, 1, True, True, True, (1 << 64) - 1, 1),
                         (True, "addition_overflow", None))
        with self.assertRaises(ValueError):
            cost(7, -1, 1, True, True, True, 0, 0)

    def test_secondary_cost_equality_and_loader_error(self):
        cost = packet.secondary_cost
        self.assertEqual(cost(100, 25, 50, 124, 0), ("unfunded_before_lookup", None, None))
        self.assertEqual(cost(100, 25, 50, 125, 0), ("ok", True, 125))
        self.assertEqual(cost(100, 25, 50, 174, 1), ("ok", True, 175))
        self.assertEqual(cost(100, 25, 50, 175, 1), ("ok", False, 175))
        self.assertEqual(cost(100, 25, 50, 175, 2), ("loader_error", False, None))

    def test_secondary_cost_distinguishes_two_overflows(self):
        maximum = (1 << 64) - 1
        self.assertEqual(packet.secondary_cost(maximum, 1, 0, maximum, 0),
                         ("extension_overflow", None, None))
        self.assertEqual(packet.secondary_cost(maximum - 1, 0, 2, maximum, 0),
                         ("guard_overflow", None, None))
        with self.assertRaises(ValueError):
            packet.secondary_cost(0, 0, 0, 0, 256)

    def test_accounting_deficit_and_failure_do_not_change_fields(self):
        adjust = packet.accounting_adjustment
        self.assertEqual(adjust(4, 3, 0, 8), ("underflow", 4, 3, 0))
        self.assertEqual(adjust(5, 3, 0, 8), ("ok", 0, 0, 8))
        self.assertEqual(adjust(5, 8, 0, 8), ("ok", 5, 0, 8))
        self.assertEqual(adjust(5, 10, -2, 8), ("ok", 5, 2, 6))

    def test_primary_adjustment_requires_value_and_nonzero_context_flag(self):
        choose = packet.primary_adjustment
        self.assertEqual(choose(False, 1, 77), 0)
        self.assertEqual(choose(True, 0, 77), 0)
        self.assertEqual(choose(True, 1, 77), 77)
        self.assertEqual(choose(True, 255, 77), 77)
        self.assertEqual(choose(True, 1, (1 << 64) - 1), (1 << 64) - 1)

    def test_primary_adjustment_rejects_out_of_domain(self):
        with self.assertRaises(ValueError):
            packet.primary_adjustment(1, 1, 77)
        with self.assertRaises(ValueError):
            packet.primary_adjustment(True, 256, 77)
        with self.assertRaises(ValueError):
            packet.primary_adjustment(True, 1, -1)

    def test_accounting_signed_saturation_and_domain(self):
        adjust = packet.accounting_adjustment
        maximum, minimum = (1 << 63) - 1, -(1 << 63)
        self.assertEqual(adjust(0, 1, maximum, 1), ("ok", 0, 0, maximum))
        self.assertEqual(adjust(0, (1 << 64) - 1, minimum, (1 << 64) - 1),
                         ("ok", 0, 0, minimum))
        with self.assertRaises(ValueError):
            adjust(0, 0, 1 << 63, 0)

    def test_gas_precedence_value_then_access(self):
        self.assertEqual(packet.synthetic_gas(9, 10, 1, 0, 64, 0, True, 13),
                         ("value_underflow", 9, None))
        self.assertEqual(packet.synthetic_gas(10, 10, 1, 0, 64, 0, True, 13),
                         ("access_underflow", 0, None))

    def test_gas_cap_and_exact_value_boundary(self):
        self.assertEqual(packet.synthetic_gas(100000, 9000, 100, 50000, 64, 2300, True, 13),
                         ("ok", 40900, 52300))
        self.assertEqual(packet.synthetic_gas(100000, 9000, 100, 99999, 64, 2300, False, 13),
                         ("ok", 1560, 98340))
        self.assertEqual(packet.synthetic_gas(9100, 9000, 100, 20000, 64, 2300, True, 13),
                         ("ok", 0, 2300))

    def test_legacy_revision_and_divisor_zero(self):
        self.assertEqual(packet.synthetic_gas(100, 0, 0, 101, 0, 0, False, 1),
                         ("forward_underflow", 100, None))
        self.assertEqual(packet.synthetic_gas(100, 0, 0, 100, 0, 0, False, 13),
                         ("divisor_error", 100, None))

    def test_stipend_saturates_and_input_domain(self):
        maximum = (1 << 64) - 1
        self.assertEqual(packet.synthetic_gas(maximum, 0, 0, maximum, 0, 1, True, 1),
                         ("ok", 0, maximum))
        with self.assertRaises(ValueError):
            packet.synthetic_gas(-1, 0, 0, 0, 1, 0, False, 13)
        with self.assertRaises(ValueError):
            packet.synthetic_gas(0, 0, 0, 0, 1, 0, 1, 13)


if __name__ == "__main__":
    unittest.main()
