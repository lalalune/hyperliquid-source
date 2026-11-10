#!/usr/bin/env python3
"""Tests for tools/check_cf_paths_supported115.py.

Every value asserted here is pinned by the node #115 disassembly of
rocksdb::CheckCFPathsSupported (0x5d8bb50..0x5d8bc55, 261 B, single
FDE, no .cold FDE, no LSDA) and the Status ctor at 0x61cf670, and
cross-checked against upstream RocksDB v8.1.1
db/column_family.cc:173-192 (read live) and
include/rocksdb/advanced_options.h:26-35 (the CompactionStyle
enum), with field offsets verified by compiling offsetof() against
the real v8.1.1 headers (compaction_style +0xe8, cf_paths +0x2c8,
db_paths +0x70, sizeof DbPath 0x28).
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import check_cf_paths_supported115 as m


def _opts(db=None, cf=None):
    db_opts = m.default_db_options()
    db_opts.update(db or {})
    cf_opts = m.default_cf_options()
    cf_opts.update(cf or {})
    return db_opts, cf_opts


class StatusLayoutTest(unittest.TestCase):
    def test_ok_image_is_all_zero(self):
        st = m.Status.ok()
        self.assertEqual(st.image(), bytes(16))
        self.assertTrue(st.is_ok())

    def test_error_image_byte_layout(self):
        # The ctor proves the byte layout: code u8 +0x0, subcode u8
        # +0x1, severity u8 +0x2, padding +0x3..+0x7, state_ +0x8.
        st = m.Status.error("kNotSupported",
                            "More than one CF paths are only supported "
                            "in universal and level compaction styles. ")
        img = st.image()
        self.assertEqual(img[0], 3)          # code byte
        self.assertEqual(img[1], 0)          # subcode byte
        self.assertEqual(img[2], 0)          # severity byte
        self.assertEqual(img[3:8], b"\x00" * 5)  # padding never written
        self.assertNotEqual(struct.unpack_from("<Q", img, 8)[0], 0)

    def test_state_buffer_is_msg_plus_nul(self):
        msg = m.MESSAGES["cf_paths"][0]
        st = m.status_ctor(m.CODE["kNotSupported"], msg, "")
        self.assertEqual(st.state_buffer(), msg.encode() + b"\x00")
        self.assertEqual(st.state_alloc(), 84 + 1)

    def test_ctor_joins_nonempty_msg2_with_colon_space(self):
        st = m.status_ctor(m.CODE["kNotSupported"], "a", "b")
        self.assertEqual(st.state, "a: b")
        self.assertEqual(st.state_buffer(), b"a: b\x00")
        self.assertEqual(st.state_alloc(), 5)

    def test_ctor_alloc_failure_leaves_partial_status(self):
        with self.assertRaises(m.BadAlloc) as ctx:
            m.status_ctor(m.CODE["kNotSupported"], "x", "",
                          alloc_ok=False)
        partial = ctx.exception.partial
        self.assertEqual(partial.code, 3)
        self.assertEqual(partial.subcode, 0)
        self.assertEqual(partial.severity, 0)
        self.assertIsNone(partial.state)


class ChecksTest(unittest.TestCase):
    def test_defaults_ok(self):
        db_opts, cf_opts = _opts()
        self.assertTrue(
            m.check_cf_paths_supported(db_opts, cf_opts).is_ok())

    def test_many_cf_paths_fails(self):
        db_opts, cf_opts = _opts(
            cf={"compaction_style": 2, "cf_paths_count": 2})
        st = m.check_cf_paths_supported(db_opts, cf_opts)
        self.assertEqual(st.code, 3)
        self.assertEqual(
            st.state,
            "More than one CF paths are only supported in universal "
            "and level compaction styles. ")
        self.assertEqual(len(st.state), 84)

    def test_empty_cf_paths_many_db_paths_fails(self):
        db_opts, cf_opts = _opts(
            db={"db_paths_count": 2},
            cf={"compaction_style": 2, "cf_paths_count": 0})
        st = m.check_cf_paths_supported(db_opts, cf_opts)
        self.assertEqual(st.code, 3)
        self.assertEqual(
            st.state,
            "More than one DB paths are only supported in universal "
            "and level compaction styles. ")
        self.assertEqual(len(st.state), 84)

    def test_check_1_masks_check_2(self):
        # Both failures: the cf_paths error wins.
        db_opts, cf_opts = _opts(
            db={"db_paths_count": 2},
            cf={"compaction_style": 2, "cf_paths_count": 2})
        st = m.check_cf_paths_supported(db_opts, cf_opts)
        self.assertEqual(
            st.state,
            "More than one CF paths are only supported in universal "
            "and level compaction styles. ")

    def test_level_style_ignores_paths(self):
        db_opts, cf_opts = _opts(
            db={"db_paths_count": 2},
            cf={"compaction_style": 0, "cf_paths_count": 2})
        self.assertTrue(
            m.check_cf_paths_supported(db_opts, cf_opts).is_ok())

    def test_universal_style_ignores_paths(self):
        db_opts, cf_opts = _opts(
            db={"db_paths_count": 3},
            cf={"compaction_style": 1, "cf_paths_count": 3})
        self.assertTrue(
            m.check_cf_paths_supported(db_opts, cf_opts).is_ok())

    def test_one_cf_path_never_reads_db_paths(self):
        # A single cf path passes even with many db paths: the
        # db_paths check is only reached for empty cf_paths.
        db_opts, cf_opts = _opts(
            db={"db_paths_count": 3},
            cf={"compaction_style": 2, "cf_paths_count": 1})
        self.assertTrue(
            m.check_cf_paths_supported(db_opts, cf_opts).is_ok())

    def test_empty_cf_paths_one_db_path_ok(self):
        db_opts, cf_opts = _opts(
            db={"db_paths_count": 1},
            cf={"compaction_style": 3, "cf_paths_count": 0})
        self.assertTrue(
            m.check_cf_paths_supported(db_opts, cf_opts).is_ok())

    def test_out_of_range_style_still_checks_paths(self):
        # The gate is an unsigned byte compare against 1, so a
        # style byte of 255 (or 4) falls into the path checks.
        db_opts, cf_opts = _opts(
            cf={"compaction_style": 255, "cf_paths_count": 2})
        st = m.check_cf_paths_supported(db_opts, cf_opts)
        self.assertEqual(st.code, 3)
        db_opts, cf_opts = _opts(
            cf={"compaction_style": 255, "cf_paths_count": 0})
        self.assertTrue(
            m.check_cf_paths_supported(db_opts, cf_opts).is_ok())

    def test_failing_check_numbers(self):
        db_opts, cf_opts = _opts()
        self.assertEqual(m._failing_check(db_opts, cf_opts), 0)
        db_opts, cf_opts = _opts(
            cf={"compaction_style": 2, "cf_paths_count": 2})
        self.assertEqual(m._failing_check(db_opts, cf_opts), 1)
        db_opts, cf_opts = _opts(
            db={"db_paths_count": 2},
            cf={"compaction_style": 2, "cf_paths_count": 0})
        self.assertEqual(m._failing_check(db_opts, cf_opts), 2)
        db_opts, cf_opts = _opts(
            db={"db_paths_count": 2},
            cf={"compaction_style": 2, "cf_paths_count": 2})
        self.assertEqual(m._failing_check(db_opts, cf_opts), 1)
        db_opts, cf_opts = _opts(
            db={"db_paths_count": 2},
            cf={"compaction_style": 1, "cf_paths_count": 2})
        self.assertEqual(m._failing_check(db_opts, cf_opts), 0)


class ThrowTest(unittest.TestCase):
    def test_bad_alloc_in_cf_paths_status_ctor(self):
        db_opts, cf_opts = _opts(
            cf={"compaction_style": 2, "cf_paths_count": 2})
        with self.assertRaises(m.BadAlloc) as ctx:
            m.check_cf_paths_supported(
                db_opts, cf_opts, fail_at="status-ctor:cf-paths")
        err = ctx.exception
        self.assertEqual(err.site, 0x5D8BC0E)
        self.assertIsNone(err.pad)
        self.assertEqual(err.cleanup, [])
        self.assertEqual(err.partial.code, 3)
        self.assertIsNone(err.partial.state)

    def test_bad_alloc_in_db_paths_status_ctor(self):
        db_opts, cf_opts = _opts(
            db={"db_paths_count": 2},
            cf={"compaction_style": 2, "cf_paths_count": 0})
        with self.assertRaises(m.BadAlloc) as ctx:
            m.check_cf_paths_supported(
                db_opts, cf_opts, fail_at="status-ctor:db-paths")
        err = ctx.exception
        self.assertEqual(err.site, 0x5D8BC0E)
        self.assertIsNone(err.pad)
        self.assertEqual(err.cleanup, [])
        self.assertEqual(err.partial.code, 3)
        self.assertIsNone(err.partial.state)

    def test_both_ctor_sites_share_one_call_address(self):
        # Both error paths share the single Status ctor call at
        # 0x5d8bc0e; the two fail_at names differ only in which
        # error path reaches it.
        self.assertEqual(
            m.THROW_SITES["status-ctor:cf-paths"][0],
            m.THROW_SITES["status-ctor:db-paths"][0])

    def test_canary_failure_on_ok_return(self):
        db_opts, cf_opts = _opts()
        with self.assertRaises(m.StackCheckFailed):
            m.check_cf_paths_supported(db_opts, cf_opts,
                                       canary_ok=False)

    def test_canary_failure_on_error_return(self):
        db_opts, cf_opts = _opts(
            cf={"compaction_style": 2, "cf_paths_count": 2})
        with self.assertRaises(m.StackCheckFailed):
            m.check_cf_paths_supported(db_opts, cf_opts,
                                       canary_ok=False)

    def test_throw_with_bad_canary_still_propagates_as_bad_alloc(self):
        # No LSDA means no pad canary check: BadAlloc + a bad
        # canary propagates as BadAlloc, not StackCheckFailed.
        db_opts, cf_opts = _opts(
            cf={"compaction_style": 2, "cf_paths_count": 2})
        with self.assertRaises(m.BadAlloc):
            m.check_cf_paths_supported(
                db_opts, cf_opts, fail_at="status-ctor:cf-paths",
                canary_ok=False)

    def test_alloc_ok_false_with_no_fail_at_only_fires_on_error(self):
        db_opts, cf_opts = _opts()
        st = m.check_cf_paths_supported(db_opts, cf_opts,
                                        alloc_ok=False)
        self.assertTrue(st.is_ok())
        db_opts, cf_opts = _opts(
            cf={"compaction_style": 2, "cf_paths_count": 2})
        with self.assertRaises(m.BadAlloc):
            m.check_cf_paths_supported(db_opts, cf_opts,
                                       alloc_ok=False)


class CasesTest(unittest.TestCase):
    def test_cases_tsv_is_reproducible(self):
        import json
        rows = []
        with open(m.CASES) as fh:
            header = fh.readline().rstrip("\n").split("\t")
            for line in fh:
                rows.append(dict(zip(header,
                                     line.rstrip("\n").split("\t"))))
        self.assertEqual(len(rows), 2400)
        for row in rows[:50]:
            inputs = json.loads(row["inputs_json"])
            expected = json.loads(row["expected_json"])
            self.assertEqual(m.run_case(inputs), expected)


if __name__ == "__main__":
    unittest.main()
