#!/usr/bin/env python3
"""Tests for tools/options_dump_115.py (RE-001-options-dump-115).

Every expectation is grounded in the packet's records.json / the
binary: the 0x5d8b3c0 jump table, the #4239 registry maps, the
bool/enum value rules and the dump's branch structure.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import options_dump_115 as model  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-001-options-dump-115"


class TestEnumNames(unittest.TestCase):
    def test_named_values(self):
        self.assertEqual(model.compression_type_name(0), "NoCompression")
        self.assertEqual(model.compression_type_name(1), "Snappy")
        self.assertEqual(model.compression_type_name(2), "Zlib")
        self.assertEqual(model.compression_type_name(3), "BZip2")
        self.assertEqual(model.compression_type_name(4), "LZ4")
        self.assertEqual(model.compression_type_name(5), "LZ4HC")
        self.assertEqual(model.compression_type_name(6), "Xpress")
        self.assertEqual(model.compression_type_name(7), "ZSTD")
        self.assertEqual(model.compression_type_name(64), "ZSTDNotFinal")
        self.assertEqual(model.compression_type_name(255), "DisableOption")

    def test_default_arm_is_empty(self):
        for value in (8, 9, 63, 65, 128, 254):
            self.assertEqual(model.compression_type_name(value), "")

    def test_as_built_values_match_4239(self):
        # #4239 pinned kZSTDNotFinalCompression=64 and
        # kDisableCompressionOption=255; the jump table agrees.
        self.assertEqual(model.COMPRESSION_NAMES[64], "ZSTDNotFinal")
        self.assertEqual(model.COMPRESSION_NAMES[255], "DisableOption")


class TestRegistries(unittest.TestCase):
    def test_style_map(self):
        self.assertEqual(len(model.COMPACTION_STYLE_NAMES), 4)
        self.assertEqual(model.COMPACTION_STYLE_NAMES[1],
                         "kCompactionStyleUniversal")
        self.assertEqual(model.registry_name(
            model.COMPACTION_STYLE_NAMES, 3), "kCompactionStyleNone")
        self.assertEqual(model.registry_name(
            model.COMPACTION_STYLE_NAMES, 9), "unknown_9")

    def test_pri_map(self):
        self.assertEqual(len(model.COMPACTION_PRI_NAMES), 5)
        self.assertEqual(model.COMPACTION_PRI_NAMES[4], "kRoundRobin")
        self.assertEqual(model.registry_name(
            model.COMPACTION_PRI_NAMES, 7), "unknown_7")

    def test_stop_style_map(self):
        self.assertEqual(len(model.COMPACTION_STOP_STYLE_NAMES), 2)
        self.assertEqual(model.COMPACTION_STOP_STYLE_NAMES[1],
                         "kCompactionStopStyleTotalSize")

    def test_registry_addresses(self):
        self.assertEqual(model.STYLE_REGISTRY, 0x6507260)
        self.assertEqual(model.PRI_REGISTRY, 0x6507220)
        self.assertEqual(model.STOP_STYLE_REGISTRY, 0x65071E0)


class TestHelperGate(unittest.TestCase):
    def test_header_always_emits(self):
        for logger_level in range(6):
            self.assertTrue(model.should_log(logger_level, 5))

    def test_info_gate(self):
        self.assertTrue(model.should_log(1, 1))
        self.assertTrue(model.should_log(0, 1))
        self.assertFalse(model.should_log(2, 1))
        self.assertFalse(model.should_log(5, 1))

    def test_level_constants(self):
        self.assertEqual((model.DEBUG_LEVEL, model.INFO_LEVEL,
                          model.WARN_LEVEL, model.ERROR_LEVEL,
                          model.FATAL_LEVEL, model.HEADER_LEVEL),
                         (0, 1, 2, 3, 4, 5))


class TestDumpLines(unittest.TestCase):
    def test_bool_strings(self):
        self.assertEqual(model.bool_str(0), "false")
        self.assertEqual(model.bool_str(1), "true")
        self.assertEqual(model.bool_str(0xFF), "true")

    def test_empty_compression_list_logs_scalar(self):
        lines = model.dump_lines({"compression": 7})
        self.assertIn("Options.compression: ZSTD", lines)
        self.assertFalse(any("compression[" in line for line in lines))

    def test_nonempty_compression_list_logs_per_level(self):
        lines = model.dump_lines({"compression_per_level": [0, 7, 64]})
        self.assertIn("Options.compression[0]: NoCompression", lines)
        self.assertIn("Options.compression[1]: ZSTD", lines)
        self.assertIn("Options.compression[2]: ZSTDNotFinal", lines)
        self.assertFalse(any(line.strip().startswith(
            "Options.compression:") for line in lines))

    def test_bottommost_ff_is_disabled(self):
        lines = model.dump_lines({"bottommost_compression": 0xFF})
        self.assertIn("Options.bottommost_compression: Disabled",
                      lines)

    def test_bottommost_other_uses_enum_name(self):
        lines = model.dump_lines({"bottommost_compression": 1})
        self.assertIn("Options.bottommost_compression: Snappy",
                      lines)

    def test_null_names(self):
        lines = model.dump_lines({})
        self.assertIn("Options.merge_operator: None", lines)
        self.assertIn("Options.prefix_extractor: nullptr", lines)

    def test_canonical_factories(self):
        lines = model.dump_lines({"table_factory": "default",
                                  "sst_partitioner_factory": "default"})
        self.assertIn("Options.table_factory: BlockBasedTable",
                      lines)
        self.assertIn("Options.sst_partitioner_factory: "
                      "SstPartitionerFixedPrefixFactory", lines)

    def test_blob_cache_null_skips_three_lines(self):
        with_cache = model.dump_lines({"blob_cache": "SharedCache"})
        without_cache = model.dump_lines({"blob_cache": None})
        self.assertEqual(len(with_cache) - len(without_cache), 3)
        self.assertFalse(any("blob_cache" in line
                             for line in without_cache))

    def test_prepopulated_values(self):
        flush = model.dump_lines({"blob_cache": "C",
                                  "blob_cache_prepopulated": 1})
        disabled = model.dump_lines({"blob_cache": "C",
                                     "blob_cache_prepopulated": 0})
        self.assertIn("blob_cache prepopulated: flush only", flush)
        self.assertIn("blob_cache prepopulated: disabled", disabled)

    def test_line_counts(self):
        # 91 main-body lines; each loop adds (n - 1) over its single
        # call site in the count, and the blob-cache null skip
        # removes 3.
        base = model.dump_lines({"compression_per_level": [7]})
        self.assertEqual(len(base), 87)  # 91 - 3 blob - 1 empty loop
        three = model.dump_lines({"compression_per_level": [7, 0, 1]})
        self.assertEqual(len(three), 89)
        empty = model.dump_lines({})
        self.assertEqual(len(empty), 87)
        with_cache = model.dump_lines(
            {"blob_cache": "C", "compression_per_level": [7]})
        self.assertEqual(len(with_cache), 90)
        full = model.dump_lines(
            {"blob_cache": "C", "compression_per_level": [7, 0, 1],
             "max_bytes_for_level_multiplier_additional": [1, 2]})
        self.assertEqual(len(full), 94)


class TestFieldTableSync(unittest.TestCase):
    def test_model_fields_match_records(self):
        records = json.loads((PACKET / "records.json").read_text())
        packet_fields = [(f["line"], f["format"].strip(),
                          int(f["offset"], 16), f["kind"])
                         for f in records["fields"]]
        model_fields = [(line, fmt, off, kind)
                        for line, fmt, off, kind, _ in model.FIELDS]
        self.assertEqual(model_fields, packet_fields)
        self.assertEqual(len(model.FIELDS), 93)
        self.assertEqual(model.FIELD_COUNT, 93)

    def test_function_ranges(self):
        self.assertEqual(model.DUMP_FUNCTION, (0x60B50C0, 0x60B79A6))
        self.assertEqual(model.HELPER_FUNCTION, (0x5FCEDA0, 0x5FCEE93))
        self.assertEqual(model.ENUMFN_FUNCTION, (0x5D8B3C0, 0x5D8B4CB))
        self.assertEqual(model.HOST_FUNCTION, (0x5D954B0, 0x5D96890))
        self.assertEqual(model.DUMP_HELPER_CALLS, 93)
        self.assertEqual(model.HELPER_DIRECT_CALLERS, 341)


if __name__ == "__main__":
    unittest.main()
