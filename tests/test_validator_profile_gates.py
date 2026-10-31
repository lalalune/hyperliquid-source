"""Tests for tools/validator_profile_gates.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-validator-profile-gates-94"
spec_ = importlib.util.spec_from_file_location("validator_profile_gates", ROOT / "tools" / "validator_profile_gates.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["validator_profile_gates"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
TOP = 0xFFFFFFFFFFFFFFFF


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE)


def run(**fields):
    case = tool.Case("t", **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case, HARNESS.before), case.__dict__
    return got


def status(got):
    return struct.unpack_from("<H", got[2], tool.OUT - tool.HEAP_BASE)[0]


def names(got):
    return [event[0] for event in got[1]]


def corrupted(va, value):
    bad = copy.copy(IMAGE)
    data = bytearray(IMAGE.blob)
    data[IMAGE.offset(va)] = value
    bad.blob = bytes(data)
    bad.relative_map = None
    return bad


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_nobits_section_does_not_resolve(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])

    def test_function_bounds(self):
        self.assertEqual(IMAGE.exact_fde(tool.GATE), (tool.GATE, tool.GATE + 506))
        self.assertEqual(IMAGE.exact_fde(tool.SCAN), (tool.SCAN, tool.SCAN + 1485))

    def test_mid_function_is_not_an_fde_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.GATE + 1)

    def test_every_gate_row_is_reached(self):
        self.assertEqual(RESULT["unreached"][tool.GATE], [])

    def test_scan_leaves_only_the_end_panic(self):
        self.assertTrue(all(va >= 0x3992519 for va in RESULT["unreached"][tool.SCAN]))
        self.assertEqual(len(RESULT["unreached"][tool.SCAN]), 9)


class Lengths(unittest.TestCase):
    def test_name_bounds(self):
        self.assertEqual([status(run(name_len=n)) for n in (0, 1, 50, 51, TOP)], [0x121, 0x186, 0x186, 0x121, 0x121])

    def test_description_bounds(self):
        self.assertEqual([status(run(desc_len=n)) for n in (0, 1, 1000, 1001, TOP)], [0x122, 0x186, 0x186, 0x122, 0x122])

    def test_name_before_description(self):
        self.assertEqual(status(run(name_len=0, desc_len=0)), 0x121)

    def test_pieces_cover_the_domain(self):
        rows = RESULT["pieces"]
        self.assertEqual([(row[1], row[2]) for row in rows[:3]], [(0, 0), (1, 50), (51, TOP)])
        self.assertEqual([(row[1], row[2]) for row in rows[3:]], [(0, 0), (1, 1000), (1001, TOP)])

    def test_window_has_no_other_operation(self):
        rows = copy.copy(RESULT["table"][tool.GATE])
        fake = copy.copy(rows[0])
        fake.va, fake.op = tool.IP_OK, "imul3"
        with self.assertRaises(tool.EvidenceError):
            tool.compare_only(rows + [fake])


class Commission(unittest.TestCase):
    def test_cap_at_register(self):
        self.assertEqual([status(run(commission=x)) for x in (0, 10000, 10001, TOP)], [0x186, 0x186, 0x123, 0x123])

    def test_register_passes_above_one_percent(self):
        self.assertEqual(status(run(commission=9999)), 0x186)

    def test_rise_stops_at_100(self):
        self.assertEqual(status(run(commission=100, cl=1, prev=0)), 0x186)
        self.assertEqual(status(run(commission=101, cl=1, prev=0)), 0x123)
        self.assertEqual(status(run(commission=101, cl=1, prev=100)), 0x123)

    def test_fall_and_same_pass(self):
        self.assertEqual(status(run(commission=9000, cl=1, prev=10000)), 0x186)
        self.assertEqual(status(run(commission=9000, cl=1, prev=9000)), 0x186)

    def test_rise_by_one_above_the_stored_value_refused(self):
        self.assertEqual(status(run(commission=9001, cl=1, prev=9000)), 0x123)

    def test_cap_beats_a_higher_stored_value(self):
        self.assertEqual(status(run(commission=10001, cl=1, prev=TOP)), 0x123)

    def test_only_bit_zero_of_the_flag_counts(self):
        self.assertEqual(status(run(commission=500, cl=2, prev=100)), 0x186)
        self.assertEqual(status(run(commission=500, cl=3, prev=100)), 0x123)

    def test_grid_rule(self):
        for x in tool.GRID:
            for prev in tool.GRID:
                run(commission=x, cl=1, prev=prev)


class Ip(unittest.TestCase):
    def test_refused_count_matches_the_blocks(self):
        self.assertEqual(RESULT["ip"]["refused"], sum(size for _, size in tool.REFUSED_BLOCKS))
        self.assertEqual(RESULT["ip"]["refused"], 51512319)

    def test_classes_cover_every_address(self):
        self.assertEqual(RESULT["ip"]["total"], 1 << 32)
        for groups in RESULT["ip"]["classes"]:
            self.assertEqual(sorted(value for group in groups for value in group), list(range(256)))

    def test_edges(self):
        for ip, want in (((192, 0, 0, 8), 0x120), ((192, 0, 0, 9), 0x186), ((192, 0, 0, 10), 0x186), ((192, 0, 0, 11), 0x120), ((172, 15, 0, 1), 0x186), ((172, 16, 0, 1), 0x120), ((172, 31, 0, 1), 0x120), ((172, 32, 0, 1), 0x186), ((255, 255, 255, 255), 0x120), ((255, 255, 255, 254), 0x186)):
            self.assertEqual(status(run(ip=ip)), want, ip)

    def test_set_member_skips_the_rule(self):
        self.assertEqual(status(run(ip=(10, 0, 0, 1), dl=1)), 0x186)

    def test_byte_two_of_the_flag_is_not_read(self):
        self.assertEqual(status(run(ip=(10, 0, 0, 1), dl=0x100)), 0x120)

    def test_tag_bit_zero_skips_the_rule(self):
        self.assertEqual(status(run(ip=(10, 0, 0, 1), ip_tag=1)), 0x186)
        self.assertEqual(status(run(ip=(10, 0, 0, 1), ip_tag=2)), 0x120)

    def test_walker_sees_a_changed_constant(self):
        bad = corrupted(0x3BFCC2E + 2, 0xA8)
        with self.assertRaises(tool.EvidenceError):
            tool.prove_ip(tool.Harness(bad))

    def test_walker_stops_on_an_unmodelled_row(self):
        bad = corrupted(0x3BFCC48, 0x90)
        with self.assertRaises((tool.EvidenceError, tool.Halt, KeyError, TypeError)):
            tool.walk_ip(bad, 0)

    def test_set_walk_has_no_refusal(self):
        self.assertEqual({row[0] for row in tool.path_rows(tool.walk_ip(IMAGE, 1))}, {"pass"})


class Copies(unittest.TestCase):
    def test_success_copies_the_profile_and_frees_nothing(self):
        got = run()
        at = tool.OUT - tool.HEAP_BASE
        self.assertEqual(got[2][at + 8:at + 0x60], tool.profile_bytes(tool.Case("t")))
        self.assertEqual(names(got), [])

    def test_refusal_frees_both_strings(self):
        self.assertEqual(run(name_len=0)[1], (("free", tool.NAME_TEXT, 16, 0), ("free", tool.DESC_TEXT, 32, 0)))

    def test_refusal_skips_a_zero_capacity(self):
        self.assertEqual(run(name_len=0, name_cap=0)[1], (("free", tool.DESC_TEXT, 32, 0),))

    def test_refusal_writes_only_the_word(self):
        got = run(name_len=0)
        at = tool.OUT - tool.HEAP_BASE
        self.assertEqual(got[2][at + 2:at + 0x60], tool.blank()[2:])


class Scan(unittest.TestCase):
    def test_same_ip(self):
        self.assertEqual(status(run(rows=(tool.other(0x10, ip=(8, 8, 8, 8)),))), 0x124)

    def test_same_signer(self):
        self.assertEqual(status(run(rows=(tool.other(0x10, signer=tool.SIGNER),))), 0x125)

    def test_ip_wins_inside_one_row(self):
        self.assertEqual(status(run(rows=(tool.other(0x10, signer=tool.SIGNER, ip=(8, 8, 8, 8)),))), 0x124)

    def test_key_order_decides_between_rows(self):
        self.assertEqual(status(run(rows=(tool.other(0x10, signer=tool.SIGNER), tool.other(0x40, ip=(8, 8, 8, 8))))), 0x125)

    def test_own_row_is_skipped(self):
        self.assertEqual(status(run(rows=(tool.Row(tool.VALIDATOR, tool.SIGNER, 0, (8, 8, 8, 8)),))), 0x186)

    def test_gate_refusal_stops_before_the_rows(self):
        self.assertEqual(status(run(name_len=0, rows=(tool.other(0x10, signer=tool.SIGNER),))), 0x121)

    def test_scan_refusal_frees(self):
        self.assertEqual(names(run(rows=(tool.other(0x10, ip=(8, 8, 8, 8)),))), ["chain", "free", "free"])

    def test_tag_one_compares_one_byte(self):
        self.assertEqual(status(run(ip_tag=1, ip=(7, 1, 2, 3), rows=(tool.other(0x10, tag=1, ip=(7, 9, 9, 9)),))), 0x124)

    def test_tags_must_match(self):
        self.assertEqual(status(run(rows=(tool.other(0x10, tag=1, ip=(8, 8, 8, 8)),))), 0x186)

    def test_set_lookup_feeds_the_gate(self):
        self.assertEqual(status(run(ip=(10, 0, 0, 1), rows=(), members=(tool.VALIDATOR,))), 0x186)
        self.assertEqual(status(run(ip=(10, 0, 0, 1), rows=(), members=(tool.key_of(0x10),))), 0x120)
        self.assertEqual(status(run(ip=(10, 0, 0, 1), rows=(), set_root=False)), 0x120)

    def test_heights_walk_every_row(self):
        for height in (1, 7, 8, 9, 16, 17):
            rows = tuple(tool.other(0x40 + at) for at in range(6)) + (tool.other(0x70, ip=(8, 8, 8, 8)),)
            self.assertEqual(status(run(rows=rows, height=height)), 0x124, height)

    def test_previous_value_reaches_the_gate(self):
        self.assertEqual(status(run(rows=(), commission=500, cl=1, prev=100)), 0x123)
        self.assertEqual(status(run(rows=(), commission=500, cl=1, prev=500)), 0x186)


class Facts(unittest.TestCase):
    def test_gate_slot_negative(self):
        data = bytearray(IMAGE.blob)
        bad = copy.copy(IMAGE)
        bad.blob = bytes(data)
        bad.relative = lambda: {}
        with self.assertRaises(tool.EvidenceError):
            tool.slot_rows(bad)

    def test_pin_negative(self):
        with self.assertRaises(tool.EvidenceError):
            tool.pin_rows(corrupted(0x3995AFA + 2, 0))

    def test_status_text(self):
        table = {row[0]: row[2] for row in RESULT["statuses"]}
        self.assertTrue(table["0x123"].endswith("it cannot exceed 1%."))
        self.assertEqual(table["0x121"], "Validator name must be between 1 and {50}")
        self.assertEqual(table["0x122"], "Validator description must be between 1 and {1000}")

    def test_status_shape_negative(self):
        arm = 0x3801A80
        at = bytes(IMAGE.blob[IMAGE.offset(arm):IMAGE.offset(arm) + 64]).find(b"\x48\x8d\x35")
        with self.assertRaises(tool.EvidenceError):
            tool.status_rows(corrupted(arm + at + 7, 0x90))

    def test_format_literal_negative(self):
        with self.assertRaises(tool.EvidenceError):
            tool.status_rows(corrupted(0x20B0F8, 0x33))


class Mutation(unittest.TestCase):
    def test_counts(self):
        rows = RESULT["mutations"]
        survivors = sorted((row[0], row[1]) for row in rows if row[2] == "survived")
        self.assertEqual(survivors, sorted(tool.EXPECTED_SURVIVORS))
        self.assertGreater(len(rows), 200)

    def test_rule_edit_is_seen(self):
        original = tool.spec_run

        def wrong(case, before):
            rule = tool.RISE_MAX
            tool.RISE_MAX = 101
            try:
                return original(case, before)
            finally:
                tool.RISE_MAX = rule
        tool.spec_run = wrong
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_cases(HARNESS, tool.named_cases())
        finally:
            tool.spec_run = original


class Packet(unittest.TestCase):
    def test_evidence_files_match(self):
        for name, text in tool.render(RESULT).items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest(self):
        rows = [line.split("  ") for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines()]
        listed = sorted(name for _, name in rows)
        self.assertEqual(listed, sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"))
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_json_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["ip_total_addresses"], 1 << 32)
        self.assertEqual(data["mutations"]["survived"], len(tool.EXPECTED_SURVIVORS))


if __name__ == "__main__":
    unittest.main()
