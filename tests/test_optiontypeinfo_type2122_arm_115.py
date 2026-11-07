"""Tests for the OptionTypeInfo type-21/22 arm model (node #115).

Ground: research/work-items/RE-001-optiontypeinfo-type2122-arm-115/records.json.
Every expectation traces to a pinned address or literal in that packet.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from optiontypeinfo_type2122_arm_115 import (
    TYPE22_ENTRIES, REACHABLE_ENTRIES, CUSTOM_PARSE_ENTRIES, PARSE_PAIRS,
    entry_by_name, reaches_arm, effective_flags, parse_map, custom_parse,
    equals_path, no_equals_path, apply_arm, serialize_type22, BSS_NULL_NAME,
)


class TestCensus(unittest.TestCase):
    def test_fifteen_type22_zero_type21(self):
        self.assertEqual(len(TYPE22_ENTRIES), 15)
        self.assertTrue(all(e[2] == 22 for e in TYPE22_ENTRIES))
        self.assertEqual({e[1] for e in TYPE22_ENTRIES},
                         REACHABLE_ENTRIES | CUSTOM_PARSE_ENTRIES)

    def test_reachability_split(self):
        self.assertEqual(len(REACHABLE_ENTRIES), 10)
        self.assertEqual(len(CUSTOM_PARSE_ENTRIES), 5)
        self.assertEqual(REACHABLE_ENTRIES, {
            "comparator", "merge_operator", "compaction_filter",
            "compaction_filter_factory", "table_factory",
            "sst_partitioner_factory", "memtable", "memtable_factory",
            "block_based_table_factory", "plain_table_factory"})
        self.assertTrue(all(reaches_arm(n) for n in REACHABLE_ENTRIES))
        self.assertTrue(all(not reaches_arm(n) for n in CUSTOM_PARSE_ENTRIES))

    def test_every_stored_entry_hits_the_flags_gate(self):
        # Only type-22 entries carry 0x200/0x400/0x800, and after the
        # helper's forced 0x400 every stored type-22 entry has a bit set,
        # so the arm always derefs to the object pointer first.
        for _, name, _, _, _, _ in TYPE22_ENTRIES:
            self.assertNotEqual(effective_flags(name) & 0xE00, 0, name)

    def test_helper_forces_0x400(self):
        # prefix_extractor is stored 0x1100 (no gate bit); the helper ORs
        # 0x400 in. memtable_insert_with_hint_prefix_extractor is stored 0x0.
        self.assertEqual(entry_by_name("prefix_extractor")["flags"], 0x1100)
        self.assertEqual(effective_flags("prefix_extractor"), 0x1500)
        self.assertEqual(entry_by_name("memtable_insert_with_hint_prefix_extractor")["flags"], 0x0)
        self.assertEqual(effective_flags("memtable_insert_with_hint_prefix_extractor"), 0x400)

    def test_parse_pairs(self):
        self.assertEqual(PARSE_PAIRS["statistics"], (0x606FA80, 0x60780A0))
        self.assertEqual(PARSE_PAIRS["wal_filter"], (0x609F250, 0x609FC80))
        self.assertEqual(PARSE_PAIRS["file_checksum_gen_factory"], (0x609F370, 0x60A2360))
        self.assertEqual(PARSE_PAIRS["prefix_extractor"], (0x607D190, 0x60809E0))

    def test_entry_fields(self):
        e = entry_by_name("comparator")
        self.assertEqual((e["map"], e["type"], e["verification"], e["offset"], e["flags"]),
                         ("ImmutableCFOptions", 22, 1, 0x8, 0x202))
        e = entry_by_name("statistics")
        self.assertEqual((e["map"], e["type"], e["verification"], e["offset"], e["flags"]),
                         ("DBOptions", 22, 0, 0x48, 0x3401))
        self.assertIsNone(entry_by_name("no_such_option"))


class TestFlagsGate(unittest.TestCase):
    def test_empty_value_ok_even_without_object(self):
        self.assertEqual(apply_arm("comparator", "", False)[0], "ok")
        self.assertEqual(apply_arm("comparator", "", True)[0], "ok")

    def test_null_object_with_value_is_knotfound(self):
        kind, code, msg = apply_arm("comparator", "id=BasicStatistics", False)
        self.assertEqual((kind, code), ("error", 1))
        self.assertEqual(msg, "Could not find configurable: comparator")

    def test_custom_parse_entries_never_reach_the_arm(self):
        for name in ("statistics", "wal_filter", "prefix_extractor"):
            kind, detail = apply_arm(name, "id=BasicStatistics", True)
            self.assertEqual(kind, "delegate")
            self.assertIn("custom parse", detail)


class TestMapParser(unittest.TestCase):
    def test_single_pair(self):
        ok, pairs = parse_map("k=v")
        self.assertTrue(ok)
        self.assertEqual(pairs, {"k": "v"})

    def test_two_pairs(self):
        ok, pairs = parse_map("k=v;k2=v2")
        self.assertTrue(ok)
        self.assertEqual(pairs, {"k": "v", "k2": "v2"})

    def test_braces_stripped(self):
        ok, pairs = parse_map("{k=v;k2=v2}")
        self.assertTrue(ok)
        self.assertEqual(pairs, {"k": "v", "k2": "v2"})

    def test_trailing_separator_ok(self):
        ok, pairs = parse_map("k=v;")
        self.assertTrue(ok)
        self.assertEqual(pairs, {"k": "v"})

    def test_no_equals_is_mismatched(self):
        ok, err = parse_map("k")
        self.assertFalse(ok)
        self.assertEqual(err, (4, "Mismatched key value pair, '=' expected"))

    def test_empty_key(self):
        ok, err = parse_map("=v")
        self.assertFalse(ok)
        self.assertEqual(err, (4, "Empty key found"))

    def test_separator_before_equals_is_unexpected(self):
        ok, err = parse_map("k;v=x")
        self.assertFalse(ok)
        self.assertEqual(err, (4, "Unexpected char in key"))

    def test_double_separator_is_unexpected(self):
        ok, err = parse_map("k=v;;x=y")
        self.assertFalse(ok)
        self.assertEqual(err, (4, "Unexpected char in key"))


class TestEqualsPath(unittest.TestCase):
    def test_map_goes_to_configure_options_slot9(self):
        kind, detail = equals_path("id=BasicStatistics")
        self.assertEqual(kind, "ok")
        self.assertEqual(detail["slot"], "0x48")
        self.assertEqual(detail["configure_options_map"], {"id": "BasicStatistics"})

    def test_map_error_propagates_verbatim(self):
        # "k=v;k": '=' is present, so the map parser runs; the second pair
        # has no '=' -> the parser's kInvalidArgument propagates verbatim.
        kind, code, msg = equals_path("k=v;k")
        self.assertEqual((kind, code, msg),
                         ("error", 4, "Mismatched key value pair, '=' expected"))

    def test_value_without_equals_never_reaches_map_parser(self):
        # No '=' -> the no-'=' path (slot 0x40 check), not the map parser:
        # "k" is treated as a bare nested-option name here.
        kind, detail = equals_path("k")
        self.assertEqual(kind, "ok")
        self.assertEqual(detail["prepare_options"], "skipped")

    def test_bare_name_with_empty_stub_skips_prepare(self):
        kind, detail = equals_path("BasicStatistics")
        self.assertEqual(kind, "ok")
        self.assertEqual(detail["prepare_options"], "skipped")

    def test_bare_name_with_config_byte3_calls_prepare(self):
        kind, detail = equals_path("BasicStatistics", config_byte3=1)
        self.assertEqual(kind, "ok")
        self.assertEqual(detail["prepare_options"], "slot 0x28")

    def test_bare_name_with_real_slot40_calls_it(self):
        kind, detail = equals_path("BasicStatistics", slot40_is_empty_stub=False)
        self.assertEqual(kind, "ok")
        self.assertTrue(detail["slot40_called"])


class TestNoEqualsPath(unittest.TestCase):
    def test_unknown_name_is_knotfound(self):
        kind, code, msg = no_equals_path("nope", {})
        self.assertEqual((kind, code, msg),
                         ("error", 1, "Could not find option: nope"))

    def test_known_type22_delegates_to_0x609a740(self):
        kind, target = no_equals_path("id", {"id": "record"}, entry_type=22)
        self.assertEqual((kind, target), ("delegate", "0x609a740"))

    def test_known_other_type_calls_parse_option(self):
        kind, detail = no_equals_path("x", {"x": "record"}, entry_type=19)
        self.assertEqual(kind, "ok")
        self.assertEqual(detail["parse_option"], "slot 0x50")


class TestCustomParse(unittest.TestCase):
    def test_id_empty_resets(self):
        self.assertEqual(custom_parse("id", ""), ("ok", "shared_ptr reset to null"))

    def test_id_with_value_delegates(self):
        self.assertEqual(custom_parse("id", "x"), ("delegate", "0x61ca3d0"))

    def test_other_name_delegates(self):
        self.assertEqual(custom_parse("other", ""), ("delegate", "0x61ca3d0"))


class TestSerializer(unittest.TestCase):
    def test_null_object_default_config_emits_bss_name(self):
        # comparator flags 0x202 (no 0x100 bit); ConfigOptions+0x4 == 0
        # falls through to the 0x6508980 string (0x60bbc85/0x60bbc99).
        kind, out = serialize_type22("comparator", False)
        self.assertEqual((kind, out), ("ok", BSS_NULL_NAME))

    def test_null_object_nonzero_config_byte4_emits_empty(self):
        # Same entry, but ConfigOptions+0x4 != 0 -> "" (0x60bbd82).
        kind, out = serialize_type22("comparator", False, config_byte4=1)
        self.assertEqual((kind, out), ("ok", ""))

    def test_null_object_with_flag_0x100_emits_bss_name(self):
        # table_factory carries flags 0xc402 (0x100 set).
        kind, out = serialize_type22("table_factory", False)
        self.assertEqual((kind, out), ("ok", BSS_NULL_NAME))

    def test_present_object_main_body(self):
        kind, out = serialize_type22("comparator", True, object_options="a=1")
        self.assertEqual((kind, out), ("ok", "BasicStatistics;a=1"))

    def test_present_object_config28_eq_2_goes_to_main_body(self):
        # No stored type-22 entry carries flags 0x8000 (flags survey), so
        # the 0x60bbc15 branch is entered with the bit clear; config+0x28
        # == 2 also routes to the main body. Both give name + options.
        kind, out = serialize_type22("comparator", True, config_u32_28=2,
                                     object_options="a=1")
        self.assertEqual((kind, out), ("ok", "BasicStatistics;a=1"))


if __name__ == "__main__":
    unittest.main()
