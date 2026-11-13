#!/usr/bin/env python3
"""Tests for tools/dbimpl_validate_options115.py.

Every value asserted here is pinned by the node #115 disassembly of
rocksdb::DBImpl::ValidateOptions (0x5e5a000..0x5e5a151, main FDE)
and its .cold landing-pad FDE (0x5e59fd4..0x5e59fff), and
cross-checked against upstream RocksDB v8.1.1
db/db_impl/db_impl_open.cc:380-484 (the two-argument dispatcher and
the nine one-argument checks, read live) and db/column_family.cc
(the per-CF check order, read live via the same-era mirror). The
two callees (ColumnFamilyData::ValidateOptions 0x5d8e3b0 and
DBImpl::ValidateOptions(db_options) 0x5e59cd0) are oracles here;
only the dispatcher is reconstructed.
"""

import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import dbimpl_validate_options115 as m


def _db(**overrides):
    opts = m.default_db_options()
    opts.update(overrides)
    return opts


def _cf(**overrides):
    opts = m.default_cf_options()
    opts.update(overrides)
    return opts


def _desc(name="default", **overrides):
    return m.ColumnFamilyDescriptor(name, _cf(**overrides))


class StatusTest(unittest.TestCase):
    def test_ok_image(self):
        st = m.Status.ok()
        self.assertEqual(st.image(), bytes(16))
        self.assertTrue(st.is_ok())

    def test_error_image_layout(self):
        st = m.Status.error("kInvalidArgument",
                            "keep_log_file_num must be greater than 0")
        img = st.image()
        self.assertEqual(struct.unpack_from("<I", img, 0)[0], 4)
        self.assertEqual(struct.unpack_from("<H", img, 4)[0], 0)
        self.assertEqual(img[6:8], b"\x00\x00")  # padding never written
        self.assertNotEqual(struct.unpack_from("<Q", img, 8)[0], 0)

    def test_move_transfers_state_and_zeroes_src(self):
        dst = m.Status.error("kNotSupported", "old state")
        src = m.Status.error("kInvalidArgument", "new state")
        freed = []
        m.move_status(dst, src, freed)
        self.assertEqual(dst.code, 4)
        self.assertEqual(dst.state, "new state")
        self.assertEqual(src, m.Status.ok())
        self.assertEqual(freed, [m._state_id("old state")])

    def test_move_ok_into_error_frees_old_state(self):
        dst = m.Status.error("kCorruption", "old")
        src = m.Status.ok()
        freed = []
        m.move_status(dst, src, freed)
        self.assertEqual(dst, m.Status.ok())
        self.assertEqual(freed, [m._state_id("old")])

    def test_move_null_states_free_nothing(self):
        dst = m.Status.ok()
        src = m.Status.error("kBusy", None)
        freed = []
        m.move_status(dst, src, freed)
        self.assertEqual(dst.code, 11)
        self.assertIsNone(dst.state)
        self.assertEqual(freed, [])


class DispatcherTest(unittest.TestCase):
    def test_empty_list_runs_db_check_only(self):
        calls = {"cf": 0, "db": 0}

        def cf(db_o, cf_o):
            calls["cf"] += 1
            return m.Status.ok()

        def db(db_o):
            calls["db"] += 1
            return m.Status.ok()

        out = m.validate_options(_db(), [], cf, db)
        self.assertTrue(out.is_ok())
        self.assertEqual(calls, {"cf": 0, "db": 1})

    def test_empty_list_db_failure_returned(self):
        out = m.validate_options(
            _db(keep_log_file_num=0), [], None,
            lambda db_o: m.Status.error(
                "kInvalidArgument", "keep_log_file_num must be greater "
                "than 0"))
        self.assertEqual(out.code, 4)
        self.assertEqual(out.state,
                         "keep_log_file_num must be greater than 0")

    def test_first_cf_failure_wins_and_stops(self):
        calls = {"cf": 0, "db": 0}

        def cf(db_o, cf_o):
            calls["cf"] += 1
            if calls["cf"] == 2:
                return m.Status.error("kNotSupported", "second fails")
            return m.Status.ok()

        def db(db_o):
            calls["db"] += 1
            return m.Status.ok()

        descs = [_desc("a"), _desc("b"), _desc("c")]
        out = m.validate_options(_db(), descs, cf, db)
        self.assertEqual(out.code, 3)
        self.assertEqual(out.state, "second fails")
        self.assertEqual(calls, {"cf": 2, "db": 0})

    def test_db_check_runs_after_all_cfs_pass(self):
        calls = {"cf": 0, "db": 0}

        def cf(db_o, cf_o):
            calls["cf"] += 1
            return m.Status.ok()

        def db(db_o):
            calls["db"] += 1
            return m.Status.error("kNotSupported", "db fails")

        out = m.validate_options(_db(), [_desc("a"), _desc("b")], cf, db)
        self.assertEqual(out.code, 3)
        self.assertEqual(calls, {"cf": 2, "db": 1})

    def test_descriptor_names_never_read(self):
        # The binary reads only +0x20 (options) per descriptor; the
        # name at +0x00 is never touched, so the result is identical
        # for any names.
        a = m.validate_options(_db(), [_desc("alpha"), _desc("beta")])
        b = m.validate_options(_db(), [_desc(""), _desc("x" * 64)])
        self.assertEqual(a, b)
        self.assertTrue(a.is_ok())

    def test_cf_failure_masks_db_failure(self):
        out = m.validate_options(
            _db(keep_log_file_num=0),
            [_desc("a", compression="kNoSuchType")])
        self.assertEqual(out.code, 4)
        self.assertIn("Compression type", out.state)

    def test_five_descriptors_all_checked(self):
        calls = {"cf": 0}

        def cf(db_o, cf_o):
            calls["cf"] += 1
            return m.Status.ok()

        out = m.validate_options(_db(), [_desc("c%d" % i)
                                         for i in range(5)], cf, None)
        self.assertTrue(out.is_ok())
        self.assertEqual(calls["cf"], 5)


class ThrowTest(unittest.TestCase):
    def test_cf_throw_frees_out_state_and_resumes(self):
        def cf(db_o, cf_o):
            raise m.BadAlloc("boom")

        with self.assertRaises(m.ValidateOptionsThrow) as ctx:
            m.validate_options(_db(), [_desc("a")], cf, None)
        self.assertIsInstance(ctx.exception.cause, m.BadAlloc)
        self.assertEqual(ctx.exception.cleanup_freed, [])

    def test_cf_throw_after_prior_failure_frees_its_state(self):
        # The dispatcher returns at the first failure, so a throw
        # after a moved-in state_ needs a first call that returns
        # OK *with* a state_ (code 0, non-null state_): the
        # dispatcher moves it into out and keeps looping, and the
        # pad must free it when the second call throws. Exercised
        # through run_case's prior_state throw cases.
        out = m.run_case({
            "group": "throw",
            "descriptors": [{"name": "a"}, {"name": "b"}],
            "fail_at": "cf:1",
            "prior_state": "keep_log_file_num must be greater than 0",
        })
        self.assertEqual(out["error"], "ValidateOptionsThrow")
        self.assertEqual(out["cleanup_freed"],
                         [m._state_id("keep_log_file_num must be "
                                      "greater than 0")])

    def test_db_throw_propagates_as_validate_options_throw(self):
        def db(db_o):
            raise m.BadAlloc("db boom")

        with self.assertRaises(m.ValidateOptionsThrow) as ctx:
            m.validate_options(_db(), [_desc("a")], None, db)
        self.assertEqual(ctx.exception.cleanup_freed, [])

    def test_canary_failure_on_return(self):
        with self.assertRaises(m.StackCheckFailed):
            m.validate_options(_db(), [], None, None, canary_ok=False)

    def test_canary_failure_on_early_return(self):
        def cf(db_o, cf_o):
            return m.Status.error("kBusy", None)

        with self.assertRaises(m.StackCheckFailed):
            m.validate_options(_db(), [_desc("a")], cf, None,
                               canary_ok=False)


class DbOracleTest(unittest.TestCase):
    def test_defaults_ok(self):
        self.assertTrue(m.validate_db_options_reference(_db()).is_ok())

    def test_checks_in_upstream_order(self):
        # db_paths > 4 fires before the mmap check.
        out = m.validate_db_options_reference(_db(
            db_paths=[{"path": "/p", "target_size": 1}] * 5,
            allow_mmap_reads=True, use_direct_reads=True))
        self.assertEqual(out.code, 3)
        self.assertIn("More than four DB paths", out.state)
        # keep_log_file_num == 0 fires before the unordered_write one.
        out = m.validate_db_options_reference(_db(
            keep_log_file_num=0, unordered_write=True,
            allow_concurrent_memtable_write=False))
        self.assertIn("keep_log_file_num", out.state)

    def test_each_db_check(self):
        cases = [
            (_db(db_paths=[{"path": "/p", "target_size": 1}] * 5), 3),
            (_db(allow_mmap_reads=True, use_direct_reads=True), 3),
            (_db(allow_mmap_writes=True,
                 use_direct_io_for_flush_and_compaction=True), 3),
            (_db(keep_log_file_num=0), 4),
            (_db(unordered_write=True,
                 allow_concurrent_memtable_write=False), 4),
            (_db(unordered_write=True,
                 allow_concurrent_memtable_write=True,
                 enable_pipelined_write=True), 4),
            (_db(atomic_flush=True, enable_pipelined_write=True), 4),
            (_db(atomic_flush=True, best_efforts_recovery=True), 4),
            (_db(use_direct_io_for_flush_and_compaction=True,
                 writable_file_max_buffer_size=0), 4),
        ]
        for opts, code in cases:
            self.assertEqual(
                m.validate_db_options_reference(opts).code, code, opts)


class CfOracleTest(unittest.TestCase):
    def test_defaults_ok(self):
        self.assertTrue(
            m.validate_cf_options_reference(_db(), _cf()).is_ok())

    def test_compression_not_linked(self):
        out = m.validate_cf_options_reference(
            _db(), _cf(compression="kNoSuchType"))
        self.assertEqual(out.code, 4)
        self.assertIn("is not linked with the binary", out.state)

    def test_concurrent_writes_gate(self):
        # inplace_update_support only matters when the DB options
        # allow concurrent memtable writes.
        out = m.validate_cf_options_reference(
            _db(allow_concurrent_memtable_write=True),
            _cf(inplace_update_support=True))
        self.assertEqual(out.code, 4)
        out = m.validate_cf_options_reference(
            _db(), _cf(inplace_update_support=True))
        self.assertTrue(out.is_ok())

    def test_cf_paths_gate(self):
        out = m.validate_cf_options_reference(
            _db(), _cf(compaction_style="kCompactionStyleFIFO",
                       cf_paths=[{"path": "/a", "target_size": 1},
                                 {"path": "/b", "target_size": 2}]))
        self.assertEqual(out.code, 3)
        out = m.validate_cf_options_reference(
            _db(db_paths=[{"path": "/a", "target_size": 1},
                          {"path": "/b", "target_size": 1}]),
            _cf(compaction_style="kCompactionStyleFIFO", cf_paths=[]))
        self.assertEqual(out.code, 3)

    def test_ttl_requires_block_based_table(self):
        out = m.validate_cf_options_reference(
            _db(), _cf(ttl=3600, table_factory="PlainTableFactory"))
        self.assertEqual(out.code, 3)
        self.assertIn("TTL is only supported", out.state)
        out = m.validate_cf_options_reference(
            _db(), _cf(ttl=m.K_DEFAULT_TTL,
                       table_factory="PlainTableFactory"))
        self.assertTrue(out.is_ok())


class BindingsTest(unittest.TestCase):
    def test_fde_hashes(self):
        self.assertEqual(m.MAIN_BODY_SHA256,
                         "8b4ef72750b4932b47334802a85dd4030dab7985dc7cbf1a"
                         "964e4f8490d1b7c7")
        self.assertEqual(m.MAIN_SOURCE_SHA256,
                         "b3d3ffa353d65c669b904a080ecb7c57e809e43d76a7761"
                         "1456c4eeacb01dab8")
        self.assertEqual(m.COLD_BODY_SHA256,
                         "9a82fbb229028dc489614db7989d2521b930301f6fda856"
                         "b380bed01ed468da2")

    def test_lsda_bytes(self):
        self.assertEqual(m.MAIN_LSDA_HEX, "ffff01066a8901c50200")
        self.assertEqual(m.COLD_LSDA_HEX, "ffff010421050000")
        self.assertEqual(m.MAIN_LSDA_VA, 0x40FA2D)
        self.assertEqual(m.COLD_LSDA_VA, 0x40FA37)

    def test_layout_constants(self):
        self.assertEqual(m.DESCRIPTOR_STRIDE, 0x320)
        self.assertEqual(m.DESCRIPTOR_OPTIONS_OFF, 0x20)
        self.assertEqual(m.CF_VALIDATE_ADDR, 0x5D8E3B0)
        self.assertEqual(m.DB_VALIDATE_ADDR, 0x5E59CD0)
        self.assertEqual(m.CALLER_SITE, 0x5E62E52)
        self.assertEqual(m.CALLER_FDE, 0x5E62C50)

    def test_case_ledger_verifies(self):
        self.assertTrue(m.verify_cases())


if __name__ == "__main__":
    unittest.main()
