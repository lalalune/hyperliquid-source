#!/usr/bin/env python3
"""Tests for tools/cf_data_validate_options115.py.

Every value asserted here is pinned by the node #115 disassembly of
rocksdb::ColumnFamilyData::ValidateOptions (0x5d8e3b0..0x5d8e9c3,
1555 B, main FDE) plus its .cold FDE (0x5d8e356..0x5d8e3a5, 79 B),
the Status ctor at 0x61cf670 and the move-assign at 0x5d89b20, and
cross-checked against upstream RocksDB v8.1.1
db/column_family.cc:113-192 (the three helper oracles, read live)
and db/column_family.cc:1364-1448 (the per-CF validator, read live).
The three helpers are oracles here only in the sense that their
bodies are not reconstructed -- their observable check order and
messages ARE pinned from the v8.1.1 source they implement.
"""

import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import cf_data_validate_options115 as m


def _db(**overrides):
    opts = m.default_db_options()
    opts.update(overrides)
    return opts


def _cf(**overrides):
    opts = m.default_cf_options()
    opts.update(overrides)
    return opts


class StatusLayoutTest(unittest.TestCase):
    def test_ok_image_is_all_zero(self):
        st = m.Status.ok()
        self.assertEqual(st.image(), bytes(16))
        self.assertTrue(st.is_ok())

    def test_error_image_byte_layout(self):
        # The ctor proves the byte layout: code u8 +0x0, subcode u8
        # +0x1, severity u8 +0x2, padding +0x3..+0x7, state_ +0x8.
        st = m.Status.error("kNotSupported",
                            "TTL is only supported in Block-Based Table "
                            "format. ")
        img = st.image()
        self.assertEqual(img[0], 3)          # code byte
        self.assertEqual(img[1], 0)          # subcode byte
        self.assertEqual(img[2], 0)          # severity byte
        self.assertEqual(img[3:8], b"\x00" * 5)  # padding never written
        self.assertNotEqual(struct.unpack_from("<Q", img, 8)[0], 0)

    def test_state_buffer_is_msg_plus_nul(self):
        st = m.status_ctor(m.CODE["kInvalidArgument"],
                           "The age cutoff for blob garbage collection "
                           "should be in the range [0.0, 1.0].", "")
        self.assertEqual(
            st.state_buffer(),
            b"The age cutoff for blob garbage collection should be in "
            b"the range [0.0, 1.0].\x00")
        self.assertEqual(st.state_alloc(), 77 + 1)

    def test_ctor_joins_nonempty_msg2_with_colon_space(self):
        # The ctor's behavior at 0x61cf720 (": " written at buf+len1);
        # this FDE always passes an empty msg2, so the join never
        # fires here -- the case pins the ctor model directly.
        st = m.status_ctor(m.CODE["kInvalidArgument"], "a", "b")
        self.assertEqual(st.state, "a: b")
        self.assertEqual(st.state_buffer(), b"a: b\x00")
        self.assertEqual(st.state_alloc(), 5)

    def test_ctor_alloc_failure_leaves_partial_status(self):
        with self.assertRaises(m.BadAlloc) as ctx:
            m.status_ctor(m.CODE["kInvalidArgument"], "x", "",
                          alloc_ok=False)
        partial = ctx.exception.partial
        self.assertEqual(partial.code, 4)
        self.assertEqual(partial.subcode, 0)
        self.assertEqual(partial.severity, 0)
        self.assertIsNone(partial.state)

    def test_move_assign_moves_state_and_zeroes_source(self):
        # Status::operator=(Status&&) 0x5d89b20: copies the 6
        # bytes, moves state_, zeroes the source, frees the old
        # destination state_.
        dst = m.Status.error("kNotSupported", "old-state")
        src = m.Status.error("kInvalidArgument", "new-state")
        _dst, freed = m.move_assign(dst, src)
        self.assertEqual(dst.code, 4)
        self.assertEqual(dst.state, "new-state")
        self.assertEqual(src.code, 0)
        self.assertIsNone(src.state)
        self.assertEqual(freed, "old-state")

    def test_move_assign_self_assign_is_noop(self):
        st = m.Status.error("kNotSupported", "keep")
        _dst, freed = m.move_assign(st, st)
        self.assertEqual(st.state, "keep")
        self.assertIsNone(freed)


class TenChecksTest(unittest.TestCase):
    def test_defaults_ok(self):
        self.assertTrue(m.validate_options(_db(), _cf()).is_ok())

    def test_check1_compression_not_linked(self):
        st = m.validate_options(
            _db(), _cf(compression=1, supported_compression=[0]))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "Compression type Snappy is not linked with the binary.")
        # per-level ZSTD (7) not in [0,1] -> fails with its name.
        st2 = m.validate_options(
            _db(), _cf(compression_per_level=[7],
                       supported_compression=[0, 1]))
        self.assertEqual(
            st2.state,
            "Compression type ZSTD is not linked with the binary.")

    def test_check1_zstd_dict_rules(self):
        st = m.validate_options(
            _db(), _cf(compression_opts={
                "zstd_max_train_bytes": 1,
                "use_zstd_dict_trainer": True,
                "max_dict_bytes": 1},
                zstd_train_supported=False))
        self.assertTrue(st.state.startswith("zstd dictionary trainer"))
        st = m.validate_options(
            _db(), _cf(compression_opts={
                "zstd_max_train_bytes": 1,
                "use_zstd_dict_trainer": False,
                "max_dict_bytes": 0}))
        self.assertTrue(st.state.startswith("The dictionary size limit"))

    def test_check2_inplace_update(self):
        st = m.validate_options(
            _db(), _cf(inplace_update_support=True))
        self.assertEqual(st.code, 4)
        self.assertTrue(st.state.startswith("In-place memtable updates"))
        st = m.validate_options(
            _db(), _cf(memtable_insert_concurrently_supported=False))
        self.assertTrue(st.state.startswith("Memtable doesn't concurrent"))

    def test_check2_skipped_when_concurrent_off(self):
        # allow_concurrent_memtable_write=false skips the helper:
        # inplace_update_support alone is not an error here.
        self.assertTrue(m.validate_options(
            _db(allow_concurrent_memtable_write=False),
            _cf(inplace_update_support=True)).is_ok())

    def test_check3_unordered_merges(self):
        st = m.validate_options(
            _db(unordered_write=True), _cf(max_successive_merges=1))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "max_successive_merges > 0 is incompatible with "
            "unordered_write")
        self.assertTrue(m.validate_options(
            _db(unordered_write=True), _cf(max_successive_merges=0))
            .is_ok())
        self.assertTrue(m.validate_options(
            _db(unordered_write=False), _cf(max_successive_merges=1))
            .is_ok())

    def test_check4_cf_paths(self):
        st = m.validate_options(
            _db(), _cf(compaction_style=2, cf_paths_count=2))
        self.assertEqual(st.code, 3)
        self.assertTrue(st.state.startswith("More than one CF paths"))
        st = m.validate_options(
            _db(db_paths_count=2),
            _cf(compaction_style=2, cf_paths_count=0))
        self.assertTrue(st.state.startswith("More than one DB paths"))
        self.assertTrue(m.validate_options(
            _db(db_paths_count=2),
            _cf(compaction_style=0, cf_paths_count=0)).is_ok())

    def test_check5_ttl(self):
        st = m.validate_options(
            _db(), _cf(ttl=100, table_factory_is_block_based=False))
        self.assertEqual(st.code, 3)
        self.assertEqual(
            st.state,
            "TTL is only supported in Block-Based Table format. ")
        self.assertTrue(m.validate_options(
            _db(), _cf(ttl=m.K_DEFAULT_TTL,
                       table_factory_is_block_based=False)).is_ok())
        self.assertTrue(m.validate_options(
            _db(), _cf(ttl=100,
                       table_factory_is_block_based=True)).is_ok())

    def test_check6_periodic(self):
        st = m.validate_options(
            _db(), _cf(periodic_compaction_seconds=100,
                       table_factory_is_block_based=False))
        self.assertEqual(st.code, 3)
        self.assertEqual(
            st.state,
            "Periodic Compaction is only supported in Block-Based "
            "Table format. ")
        self.assertTrue(m.validate_options(
            _db(), _cf(periodic_compaction_seconds=m.K_DEFAULT_TTL,
                       table_factory_is_block_based=False)).is_ok())

    def test_check7_age_cutoff_boundaries(self):
        for value, ok in [(0.0, True), (1.0, True), (0.5, True),
                          (-1e-9, False), (1.0 + 1e-9, False)]:
            st = m.validate_options(
                _db(), _cf(enable_blob_garbage_collection=True,
                           blob_garbage_collection_age_cutoff=value))
            self.assertEqual(st.is_ok(), ok, value)
        st = m.validate_options(
            _db(), _cf(enable_blob_garbage_collection=True,
                       blob_garbage_collection_age_cutoff=1.5))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "The age cutoff for blob garbage collection should be in "
            "the range [0.0, 1.0].")

    def test_check7_nan_passes(self):
        # comisd: NaN is unordered, so neither `ja` nor the
        # range check fires -- the same as the source
        # `x < 0.0 || x > 1.0`, which is false for NaN.
        self.assertTrue(m.validate_options(
            _db(), _cf(enable_blob_garbage_collection=True,
                       blob_garbage_collection_age_cutoff=float("nan"),
                       blob_garbage_collection_force_threshold=
                       float("nan"))).is_ok())

    def test_check8_force_threshold(self):
        st = m.validate_options(
            _db(), _cf(enable_blob_garbage_collection=True,
                       blob_garbage_collection_force_threshold=-0.5))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "The garbage ratio threshold for forcing blob garbage "
            "collection should be in the range [0.0, 1.0].")

    def test_check9_fifo(self):
        st = m.validate_options(
            _db(max_open_files=0),
            _cf(compaction_style=2, ttl=100))
        self.assertEqual(st.code, 3)
        self.assertEqual(
            st.state,
            "FIFO compaction only supported with max_open_files = -1.")
        self.assertTrue(m.validate_options(
            _db(max_open_files=-1),
            _cf(compaction_style=2, ttl=100)).is_ok())

    def test_check9_fifo_fires_for_default_ttl(self):
        # Check 9 tests ttl as plain != 0: kDefaultTtl counts,
        # unlike check 5 where it is excluded.
        st = m.validate_options(
            _db(max_open_files=0),
            _cf(compaction_style=2, ttl=m.K_DEFAULT_TTL))
        self.assertEqual(st.code, 3)
        self.assertEqual(st.state, m.MESSAGES["fifo"][0])

    def test_check10_memtable_protection(self):
        for value in (0, 1, 2, 4, 8):
            self.assertTrue(m.validate_options(
                _db(), _cf(memtable_protection_bytes_per_key=value))
                .is_ok(), value)
        for value in (3, 5, 9, 0xFFFFFFFF):
            st = m.validate_options(
                _db(), _cf(memtable_protection_bytes_per_key=value))
            self.assertEqual(st.code, 3)
            self.assertEqual(st.state, m.MESSAGES["memtable"][0])

    def test_first_failure_wins(self):
        # Check 1 masks check 5; check 3 masks check 10.
        db_opts = _db()
        cf_opts = _cf(compression=1, supported_compression=[0],
                      ttl=100, table_factory_is_block_based=False)
        st = m.validate_options(db_opts, cf_opts)
        self.assertEqual(m._failing_check(db_opts, cf_opts), 1)
        self.assertTrue(st.state.startswith("Compression type"))
        st = m.validate_options(
            _db(unordered_write=True),
            _cf(max_successive_merges=1,
                memtable_protection_bytes_per_key=3))
        self.assertEqual(st.state, m.MESSAGES["unordered"][0])

    def test_all_inline_messages_are_verbatim(self):
        for key, (msg, _a, ln) in m.MESSAGES.items():
            self.assertEqual(len(msg), ln, key)
        self.assertTrue(m.MESSAGES["ttl"][0].endswith(" "))
        self.assertTrue(m.MESSAGES["periodic"][0].endswith(" "))

    def test_helper_ok_with_state_propagates(self):
        # The final out = move(T2) carries a code-0-with-state
        # helper result into the returned status.
        st = m.validate_options(_db(), _cf(helper_ok_state="helper-state"))
        self.assertTrue(st.is_ok())
        self.assertEqual(st.state, "helper-state")


class ThrowTest(unittest.TestCase):
    def test_ctor_badalloc_at_each_inline_error(self):
        sites = {3: "status-ctor:unordered", 5: "status-ctor:ttl",
                 6: "status-ctor:periodic", 7: "status-ctor:age",
                 8: "status-ctor:force", 9: "status-ctor:fifo",
                 10: "status-ctor:memtable"}
        for n, site in sites.items():
            _m, overrides = m._CHECK_FAIL_OVERRIDES[n - 1]
            db_opts, cf_opts = m._opts(overrides)
            with self.assertRaises(m.BadAlloc) as ctx:
                m.validate_options(db_opts, cf_opts, fail_at=site)
            partial = ctx.exception.partial
            self.assertEqual(partial.code, m.CODE[
                m.CHECKS[n - 1][2]])
            self.assertIsNone(partial.state)
            # The memtable ctor's pad sized-deletes the vector.
            if n == 10:
                self.assertEqual(ctx.exception.pad, 0x5EF)
                self.assertIn("sized_delete_vector_20B",
                              ctx.exception.cleanup)

    def test_helper_call_throw_pads(self):
        # Compression / concurrent / cfpaths calls: generic pad.
        with self.assertRaises(m.CalleeThrow) as ctx:
            m.validate_options(_db(), _cf(), fail_at="compression-call")
        self.assertEqual(ctx.exception.pad, 0x607)
        # IsInstanceOf throws: the string-dispose pad.
        with self.assertRaises(m.CalleeThrow) as ctx:
            m.validate_options(
                _db(), _cf(ttl=100, table_factory_is_block_based=True),
                fail_at="isinstanceof-ttl")
        self.assertEqual(ctx.exception.pad, 0x5FB)
        self.assertIn("dispose_block_based_table_string",
                      ctx.exception.cleanup)
        with self.assertRaises(m.CalleeThrow) as ctx:
            m.validate_options(
                _db(),
                _cf(periodic_compaction_seconds=100,
                    table_factory_is_block_based=True),
                fail_at="isinstanceof-periodic")
        self.assertEqual(ctx.exception.pad, 0x5E3)

    def test_canary_failure_on_ok_return(self):
        with self.assertRaises(m.StackCheckFailed):
            m.validate_options(_db(), _cf(), canary_ok=False)

    def test_canary_failure_on_error_return(self):
        with self.assertRaises(m.StackCheckFailed):
            m.validate_options(
                _db(unordered_write=True),
                _cf(max_successive_merges=1), canary_ok=False)

    def test_throw_beats_canary(self):
        # A ctor throw never reaches the epilogue, so the canary
        # check does not run -- but the pad's own canary check
        # fires first and raises StackCheckFailed instead.
        with self.assertRaises(m.StackCheckFailed) as ctx:
            m.validate_options(
                _db(unordered_write=True),
                _cf(max_successive_merges=1), canary_ok=False,
                fail_at="status-ctor:unordered")
        self.assertEqual(ctx.exception.pad, 0x607)


class BindingsTest(unittest.TestCase):
    def test_hashes(self):
        self.assertEqual(
            m.BODY_SHA256,
            "4c564ac336f94f2e9a06f9a725d47902a850a87162844c5"
            "ce7691f07672591d0")
        self.assertEqual(
            m.SOURCE_SHA256,
            "7738e1c844bcbf2f687ce337478b114527447b1e9a53dc"
            "2b8de6ca535251e564")
        self.assertEqual(
            m.COLD_BODY_SHA256,
            "4df4d5cd1f379d7866ba92c9b18e0ea634492a6136623"
            "aae87e50f435c93cd9c")
        self.assertEqual(
            m.COLD_SOURCE_SHA256,
            "66b930753725447dcab71b3d141e053d0fdf2a3c43e"
            "6a4e9e92fe0b60591d162")
        self.assertEqual(m.START, 0x5D8E3B0)
        self.assertEqual(m.END, 0x5D8E9C3)
        self.assertEqual(m.END - m.START, 1555)
        self.assertEqual(m.COLD_END - m.COLD_START, 79)

    def test_callers(self):
        self.assertEqual(len(m.CALLERS), 4)
        self.assertEqual(m.CALLERS[0][0], 0x5D69A9D)  # CreateColumnFamilyImpl
        self.assertEqual(m.CALLERS[1][0], 0x5D725F6)  # SetDBOptions
        self.assertEqual(m.CALLERS[2][0], 0x5D8EB60)  # SetOptions
        self.assertEqual(m.CALLERS[3][0], 0x5E5A06A)  # dispatcher

    def test_lsda(self):
        self.assertEqual(m.LSDA_ADDR, 0x40A30F)
        self.assertEqual(len(m.LSDA_ENTRIES), 8)
        self.assertTrue(all(e[3] == 0 for e in m.LSDA_ENTRIES))
        self.assertEqual(m.COLD_LSDA_ADDR, 0x40A344)
        self.assertEqual(m.COLD_LSDA_ENTRIES, [(43, 5, 0, 0)])

    def test_result_independent_of_caller(self):
        a = m.run_case({"group": "bindings", "caller_site": "0x5d69a9d",
                        "db_overrides": {"unordered_write": True},
                        "cf_overrides": {"max_successive_merges": 1}})
        b = m.run_case({"group": "bindings", "caller_site": "0x5e5a06a",
                        "db_overrides": {"unordered_write": True},
                        "cf_overrides": {"max_successive_merges": 1}})
        self.assertEqual(a["result"], b["result"])
        self.assertEqual(a["result_sha256"], b["result_sha256"])


if __name__ == "__main__":
    unittest.main()
