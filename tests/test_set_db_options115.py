#!/usr/bin/env python3
"""Tests for tools/set_db_options115.py.

Every value asserted here is pinned by the node #115 disassembly of
rocksdb::DBImpl::SetDBOptions (0x5d71fe0..0x5d72e50, 3696 B, main FDE)
and its .cold FDE (0x5d71eea..0x5d71fe0, 246 B, 22-entry LSDA, all
cleanup), the Status ctor at 0x61cf670, and cross-checked against
upstream RocksDB v8.1.1 db/db_impl.cc:1209-1376 (read live), with
DBImpl/DBOptions field offsets verified by compiling offsetof()
against the real v8.1.1 headers (g++) and the vendored-layout
differences recorded in the packet (mutex_ +0x700,
mutable_db_options_ +0x5a0, table_cache_ +0x750,
file_options_for_compaction_ +0x8d0, write_controller_ +0x1120,
total_log_size_ +0xc28, max_total_wal_size_ +0x1860,
periodic_task_scheduler_ +0x1748, write_thread_ +0xd40).
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import set_db_options115 as m


def _new_opts(**over):
    opts = m.default_mutable_db_options()
    opts.update(over)
    return opts


def _db(**over):
    db = m.default_db_state()
    m._apply_overrides(db, over)
    return db


class StatusLayoutTest(unittest.TestCase):
    def test_ok_image_is_all_zero(self):
        st = m.Status.ok()
        self.assertEqual(st.image(), bytes(16))
        self.assertTrue(st.is_ok())

    def test_error_image_byte_layout(self):
        # The ctor proves the byte layout: code u8 +0x0, subcode u8
        # +0x1, severity u8 +0x2, padding +0x3..+0x7, state_ +0x8.
        st = m.Status.error("kInvalidArgument", "empty input")
        img = st.image()
        self.assertEqual(img[0], 4)          # code byte
        self.assertEqual(img[1], 0)          # subcode byte
        self.assertEqual(img[2], 0)          # severity byte
        self.assertEqual(img[3:8], b"\x00" * 5)  # padding never written
        self.assertNotEqual(struct.unpack_from("<Q", img, 8)[0], 0)

    def test_state_buffer_is_msg_plus_nul(self):
        msg = m.MESSAGES["empty-input"][0]
        st = m.status_ctor(m.CODE["kInvalidArgument"], msg, "")
        self.assertEqual(st.state_buffer(), msg.encode() + b"\x00")
        self.assertEqual(st.state_alloc(), 11 + 1)

    def test_ctor_joins_nonempty_msg2_with_colon_space(self):
        st = m.status_ctor(m.CODE["kIOError"],
                           m.MESSAGES["ioerror-persist"][0],
                           "IOError: x")
        self.assertEqual(
            st.state,
            "SetDBOptions() succeeded, but unable to persist options: "
            "IOError: x")
        self.assertEqual(st.state_buffer(),
                         (m.MESSAGES["ioerror-persist"][0] +
                          ": IOError: x").encode() + b"\x00")
        self.assertEqual(st.state_alloc(), 55 + 2 + 10 + 1)

    def test_ctor_alloc_failure_leaves_partial_status(self):
        with self.assertRaises(m.BadAlloc) as ctx:
            m.status_ctor(m.CODE["kInvalidArgument"], "x", "",
                          alloc_ok=False, site=0x5D7208B, pad=None,
                          cleanup=[])
        partial = ctx.exception.partial
        self.assertEqual(partial.code, 4)
        self.assertEqual(partial.subcode, 0)
        self.assertEqual(partial.severity, 0)
        self.assertIsNone(partial.state)
        self.assertEqual(ctx.exception.site, 0x5D7208B)
        self.assertIsNone(ctx.exception.pad)
        self.assertEqual(ctx.exception.cleanup, [])


class ChecksTest(unittest.TestCase):
    def test_empty_input_returns_invalid_argument(self):
        out = m.set_db_options(m.default_db_state(), [])
        self.assertEqual(out["result"].code, 4)
        self.assertEqual(out["result"].state, "empty input")
        self.assertEqual(out["effects"], [])
        self.assertEqual(
            out["log"][0]["message"],
            "[db/db_impl/db_impl.cc:1212] SetDBOptions(), empty input.")

    def test_unchanged_options_short_circuit(self):
        # The short-circuit compares the parsed options AFTER the
        # bytes_per_sync 1 MiB default, so the db's mutable must
        # already carry bytes_per_sync=1048576.
        db = _db(mutable={"bytes_per_sync": 1048576})
        out = m.set_db_options(db, [["max_background_jobs", "4"]],
                               parse_new_options=_new_opts())
        self.assertTrue(out["result"].is_ok())
        self.assertTrue(any("not changed" in l["message"]
                            for l in out["log"]))
        self.assertIn("mutex Unlock (0x60d52f0)", out["effects"])

    def test_default_db_never_short_circuits(self):
        # A default db has bytes_per_sync 0; the parsed options
        # default it to 1 MiB, so they differ and the full path runs.
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4))
        self.assertTrue(out["result"].is_ok())
        self.assertTrue(any("succeeded" in l["message"]
                            for l in out["log"]))
        self.assertFalse(any("not changed" in l["message"]
                             for l in out["log"]))

    def test_parse_failure_returns_parse_status(self):
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "4"]],
            parse={"code": 4, "subcode": 0, "severity": 0,
                   "state": "bad option"})
        self.assertEqual(out["result"].code, 4)
        self.assertEqual(out["result"].state, "bad option")

    def test_bytes_per_sync_defaults_to_1mib(self):
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4))
        self.assertEqual(
            m._db_summary(out["db"])["mutable"]["bytes_per_sync"],
            1048576)
        self.assertIn("bytes_per_sync 0 -> 1048576", out["effects"])

    def test_validate1_failure_returns_its_status(self):
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4),
            validate1={"code": 4, "subcode": 0, "severity": 0,
                       "state": "bad options"})
        self.assertEqual(out["result"].code, 4)
        self.assertEqual(out["result"].state, "bad options")

    def test_per_cf_failure_first_cf(self):
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4),
            cf_statuses=[{"code": 4, "subcode": 0, "severity": 0,
                          "state": "bad cf"}])
        self.assertEqual(out["result"].code, 4)
        self.assertEqual(out["result"].state, "bad cf")

    def test_per_cf_failure_second_cf(self):
        db = _db(column_families=[m.default_column_family(0),
                                  m.default_column_family(1, "cf1")])
        out = m.set_db_options(
            db, [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4),
            cf_statuses=[None, {"code": 4, "subcode": 0, "severity": 0,
                                "state": "bad cf1"}])
        self.assertEqual(out["result"].state, "bad cf1")

    def test_dropped_cf_is_skipped(self):
        dropped = m.default_column_family(0)
        dropped["dropped"] = True
        db = _db(column_families=[dropped,
                                  m.default_column_family(1, "cf1")])
        out = m.set_db_options(
            db, [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4),
            cf_statuses=[{"code": 4, "subcode": 0, "severity": 0,
                          "state": "bad cf1"}])
        self.assertEqual(out["result"].state, "bad cf1")
        self.assertNotIn("GetLatestCFOptions cf=default", out["effects"])

    def test_jobs_growth_grows_both_pools(self):
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "16"]],
            parse_new_options=_new_opts(max_background_jobs=16))
        self.assertIn("Env::IncBackgroundThreads(HIGH, 4)",
                      out["effects"])
        self.assertIn("Env::IncBackgroundThreads(LOW, 12)",
                      out["effects"])
        self.assertIn("MaybeScheduleFlushOrCompaction", out["effects"])

    def test_no_pool_growth_when_limits_unchanged(self):
        # jobs stays at the db default (2): limits (1,1) vs (1,1),
        # so the BG-limits code runs with no IncBackgroundThreads
        # call. (jobs 2->4 would grow compactions 1->3.)
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(stats_dump_period_sec=601))
        self.assertFalse(any("IncBackgroundThreads" in e
                             for e in out["effects"]))

    def test_register_dump_failure_returns_its_status(self):
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4),
            register_dump={"code": 5, "subcode": 0, "severity": 0,
                           "state": "register failed"})
        self.assertEqual(out["result"].code, 5)
        self.assertEqual(out["result"].state, "register failed")

    def test_switch_wal_failure_is_logged_only(self):
        db = _db(total_log_size=100)
        out = m.set_db_options(
            db, [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4),
            switch_wal={"code": 5, "subcode": 0, "severity": 0,
                        "state": "switch failed"})
        self.assertTrue(out["result"].is_ok())
        self.assertTrue(any("Unable to purge WAL files" in l["message"]
                            for l in out["log"]))

    def test_persist_failure_ignored_when_fail_if_false(self):
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4),
            write_options_file={"code": 5, "subcode": 0, "severity": 0,
                                "state": "persist failed"})
        self.assertTrue(out["result"].is_ok())
        self.assertTrue(any("Unable to persist options" in l["message"]
                            for l in out["log"]))

    def test_persist_failure_is_ioerror_when_fail_if_true(self):
        db = _db(immutable={"fail_if_options_file_error": True})
        out = m.set_db_options(
            db, [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4),
            write_options_file={"code": 5, "subcode": 0, "severity": 0,
                                "state": "persist failed"})
        self.assertEqual(out["result"].code, 5)
        self.assertEqual(
            out["result"].state,
            "SetDBOptions() succeeded, but unable to persist options: "
            "IO error: persist failed")

    def test_table_cache_infinite_capacity(self):
        # max_open_files == -1 -> SetCapacity(kInfiniteCapacity 0x400000).
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4))
        self.assertEqual(
            m._db_summary(out["db"])["table_cache_capacity"], 4194304)


class ThrowTest(unittest.TestCase):
    def test_bad_alloc_in_empty_input_ctor(self):
        with self.assertRaises(m.BadAlloc) as ctx:
            m.set_db_options(m.default_db_state(), [],
                             alloc_ok=False)
        err = ctx.exception
        self.assertEqual(err.site, 0x5D7208B)
        self.assertIsNone(err.pad)
        self.assertEqual(err.cleanup, [])
        self.assertEqual(err.partial.code, 4)
        self.assertIsNone(err.partial.state)

    def test_throw_at_validate1_runs_cold_chain(self):
        with self.assertRaises(m.Throw) as ctx:
            m.set_db_options(
                m.default_db_state(), [["max_background_jobs", "4"]],
                parse_new_options=_new_opts(max_background_jobs=4),
                fail_at="validate1")
        err = ctx.exception
        self.assertEqual(err.kind, "CalleeThrew")
        self.assertEqual(err.site, 0x5D7256D)
        self.assertEqual(err.pad, 0x5D72DE4)
        self.assertEqual(err.cleanup, m._CHAIN_F41)

    def test_throw_with_bad_canary_becomes_stack_check_failed(self):
        with self.assertRaises(m.StackCheckFailed) as ctx:
            m.set_db_options(
                m.default_db_state(), [["max_background_jobs", "4"]],
                parse_new_options=_new_opts(max_background_jobs=4),
                fail_at="validate1", canary_ok=False)
        err = ctx.exception
        self.assertEqual(err.site, 0x5D7256D)
        self.assertEqual(err.pad, 0x5D72DE4)
        self.assertEqual(err.cleanup, m._CHAIN_F41)

    def test_no_pad_throw_ignores_bad_canary(self):
        # The empty-input Log has no landing pad: the throw
        # propagates with no cleanup and no canary check.
        with self.assertRaises(m.Throw) as ctx:
            m.set_db_options(m.default_db_state(), [],
                             fail_at="log-empty-input", canary_ok=False)
        err = ctx.exception
        self.assertEqual(err.kind, "CalleeThrew")
        self.assertEqual(err.site, 0x5D72033)
        self.assertIsNone(err.pad)
        self.assertEqual(err.cleanup, [])

    def test_bad_alloc_with_bad_canary_still_bad_alloc(self):
        # No pad on the empty-input Status ctor: BadAlloc +
        # a bad canary still propagates as BadAlloc.
        with self.assertRaises(m.BadAlloc):
            m.set_db_options(m.default_db_state(), [],
                             alloc_ok=False, canary_ok=False)

    def test_canary_failure_on_normal_return(self):
        with self.assertRaises(m.StackCheckFailed) as ctx:
            m.set_db_options(
                m.default_db_state(), [["max_background_jobs", "4"]],
                parse_new_options=_new_opts(max_background_jobs=4),
                canary_ok=False)
        self.assertEqual(ctx.exception.site, 0x5D720A1)

    def test_alloc_ok_false_only_fires_on_error_path(self):
        # No fail_at: alloc_ok=False fires only when an error
        # path runs the Status ctor (the empty input).
        out = m.set_db_options(
            m.default_db_state(), [["max_background_jobs", "4"]],
            parse_new_options=_new_opts(max_background_jobs=4),
            alloc_ok=False)
        self.assertTrue(out["result"].is_ok())
        with self.assertRaises(m.BadAlloc):
            m.set_db_options(m.default_db_state(), [],
                             alloc_ok=False)

    def test_throw_sites_have_pads_except_three(self):
        no_pad = [name for name, (_s, pad, _c)
                  in m.THROW_SITES.items() if pad is None]
        self.assertEqual(sorted(no_pad),
                         ["log-empty-input", "log-flush",
                          "status-ctor-empty-input"])


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

    def test_short_circuit_cases_exist(self):
        import json
        count = 0
        with open(m.CASES) as fh:
            header = fh.readline().rstrip("\n").split("\t")
            for line in fh:
                row = dict(zip(header, line.rstrip("\n").split("\t")))
                if row["group"] != "checks":
                    continue
                expected = json.loads(row["expected_json"])
                if any("not changed" in msg
                       for msg in expected.get("log", [])):
                    count += 1
        self.assertGreater(count, 0)


if __name__ == "__main__":
    unittest.main()
