#!/usr/bin/env python3
"""Tests for tools/db_options_default_ctor115.py.

Every value asserted here is pinned by the node #115 disassembly of
rocksdb::DBOptions::DBOptions() (0x60b2db0..0x60b3154) and cross-checked
against upstream RocksDB v8.1.1 include/rocksdb/options.h.
"""

import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import db_options_default_ctor115 as m


def _img(result):
    return result["image"]


def _u64(image, off):
    return struct.unpack_from("<Q", image, off)[0]


def _i32(image, off):
    return struct.unpack_from("<i", image, off)[0]


def _u32(image, off):
    return struct.unpack_from("<I", image, off)[0]


class TestDefaults(unittest.TestCase):
    def test_size_and_field_count(self):
        result = m.construct_db_options()
        self.assertEqual(len(result["image"]), 0x290)
        self.assertEqual(len(result["fields"]), 93)
        self.assertEqual(len(m.FIELDS), 93)

    def test_leading_bools(self):
        f = m.default_fields()
        self.assertEqual(
            [f[n] for n in (
                "create_if_missing", "create_missing_column_families",
                "error_if_exists", "paranoid_checks",
                "flush_verify_memtable_count",
                "track_and_verify_wals_in_manifest",
                "verify_sst_unique_id_in_manifest")],
            [False, False, False, True, True, False, True])

    def test_env_default(self):
        f = m.default_fields()
        self.assertEqual(f["env"], "env:default")
        image = _img(m.construct_db_options(env_id=0x7F0000001000))
        self.assertEqual(_u64(image, 0x08), 0x7F0000001000)

    def test_shared_pointers_null(self):
        f = m.default_fields()
        for name in ("rate_limiter", "sst_file_manager", "info_log",
                     "statistics", "write_buffer_manager", "row_cache",
                     "file_checksum_gen_factory", "compaction_service"):
            self.assertIsNone(f[name], name)
        image = _img(m.construct_db_options())
        for off in (0x10, 0x20, 0x30, 0x58, 0x158, 0x1F8, 0x228, 0x278):
            self.assertEqual(image[off:off + 16], b"\0" * 16, hex(off))
        self.assertIsNone(f["wal_filter"])
        self.assertEqual(_u64(image, 0x208), 0)

    def test_info_log_level(self):
        self.assertEqual(m.default_fields()["info_log_level"], 1)

    def test_open_files_pair(self):
        f = m.default_fields()
        self.assertEqual(f["max_open_files"], -1)
        self.assertEqual(f["max_file_opening_threads"], 16)
        image = _img(m.construct_db_options())
        self.assertEqual(_u64(image, 0x44), 0x00000010FFFFFFFF)

    def test_log_sizes(self):
        f = m.default_fields()
        self.assertEqual(f["max_total_wal_size"], 0)
        self.assertEqual(f["max_log_file_size"], 0)
        self.assertEqual(f["log_file_time_to_roll"], 0)
        self.assertEqual(f["keep_log_file_num"], 1000)
        self.assertEqual(f["recycle_log_file_num"], 0)
        self.assertEqual(f["max_manifest_file_size"], 1024 * 1024 * 1024)
        self.assertEqual(f["table_cache_numshardbits"], 6)
        self.assertEqual(f["WAL_ttl_seconds"], 0)
        self.assertEqual(f["WAL_size_limit_MB"], 0)
        self.assertEqual(f["manifest_preallocation_size"], 4 * 1024 * 1024)

    def test_delete_obsolete_period(self):
        f = m.default_fields()
        self.assertEqual(f["delete_obsolete_files_period_micros"],
                         6 * 60 * 60 * 1000000)

    def test_background_jobs(self):
        f = m.default_fields()
        self.assertEqual(f["max_background_jobs"], 2)
        self.assertEqual(f["max_background_compactions"], -1)
        self.assertEqual(f["max_subcompactions"], 1)
        self.assertEqual(f["max_background_flushes"], -1)

    def test_mmap_and_fallocate(self):
        f = m.default_fields()
        for name in ("allow_mmap_reads", "allow_mmap_writes",
                     "use_direct_reads",
                     "use_direct_io_for_flush_and_compaction"):
            self.assertIs(f[name], False, name)
        self.assertIs(f["allow_fallocate"], True)
        self.assertIs(f["is_fd_close_on_exec"], True)

    def test_stats(self):
        f = m.default_fields()
        self.assertEqual(f["stats_dump_period_sec"], 600)
        self.assertEqual(f["stats_persist_period_sec"], 600)
        self.assertIs(f["persist_stats_to_disk"], False)
        self.assertEqual(f["stats_history_buffer_size"], 1024 * 1024)
        self.assertIs(f["advise_random_on_open"], True)
        self.assertEqual(f["db_write_buffer_size"], 0)

    def test_compaction_hints(self):
        f = m.default_fields()
        self.assertEqual(f["access_hint_on_compaction_start"], 1)
        self.assertEqual(f["compaction_readahead_size"], 0)
        self.assertEqual(f["random_access_max_buffer_size"], 1024 * 1024)
        self.assertEqual(f["writable_file_max_buffer_size"], 1024 * 1024)
        self.assertIs(f["use_adaptive_mutex"], False)
        self.assertEqual(f["bytes_per_sync"], 0)
        self.assertEqual(f["wal_bytes_per_sync"], 0)
        self.assertIs(f["strict_bytes_per_sync"], False)

    def test_write_thread(self):
        f = m.default_fields()
        self.assertIs(f["enable_pipelined_write"], False)
        self.assertIs(f["unordered_write"], False)
        self.assertIs(f["allow_concurrent_memtable_write"], True)
        self.assertIs(f["enable_write_thread_adaptive_yield"], True)
        self.assertEqual(f["max_write_batch_group_size_bytes"], 1 << 20)
        self.assertEqual(f["write_thread_max_yield_usec"], 100)
        self.assertEqual(f["write_thread_slow_yield_usec"], 3)

    def test_recovery(self):
        f = m.default_fields()
        self.assertIs(f["skip_stats_update_on_db_open"], False)
        self.assertIs(f["skip_checking_sst_file_sizes_on_db_open"], False)
        self.assertEqual(f["wal_recovery_mode"], 2)
        self.assertIs(f["allow_2pc"], False)

    def test_option_file_bools(self):
        f = m.default_fields()
        for name in ("fail_if_options_file_error", "dump_malloc_stats",
                     "avoid_flush_during_recovery",
                     "avoid_flush_during_shutdown", "allow_ingest_behind",
                     "two_write_queues", "manual_wal_flush"):
            self.assertIs(f[name], False, name)
        self.assertEqual(f["wal_compression"], 0)
        self.assertIs(f["atomic_flush"], False)
        self.assertIs(f["avoid_unnecessary_blocking_io"], False)
        self.assertIs(f["write_dbid_to_manifest"], False)
        self.assertEqual(f["log_readahead_size"], 0)

    def test_error_recovery_tail(self):
        f = m.default_fields()
        self.assertIs(f["best_efforts_recovery"], False)
        self.assertEqual(f["max_bgerror_resume_count"], 2147483647)
        self.assertEqual(f["bgerror_resume_retry_interval"], 1000000)
        self.assertIs(f["allow_data_in_errors"], False)
        self.assertEqual(f["checksum_handoff_file_types"], 0)
        self.assertEqual(f["lowest_used_cache_tier"], 1)
        self.assertIs(f["enforce_single_del_contracts"], True)

    def test_containers_empty(self):
        f = m.default_fields()
        self.assertEqual(f["db_paths"], [])
        self.assertEqual(f["listeners"], [])
        image = _img(m.construct_db_options())
        self.assertEqual(image[0x70:0x88], b"\0" * 24)
        self.assertEqual(image[0x1A8:0x1C0], b"\0" * 24)

    def test_empty_strings_sso(self):
        f = m.default_fields()
        self.assertEqual(f["db_log_dir"], b"")
        self.assertEqual(f["wal_dir"], b"")
        image = _img(m.construct_db_options())
        # ptr -> own SSO buffer, size 0, NUL at buffer[0].
        self.assertEqual(_u64(image, 0x88), m.THIS_BASE + 0x98)
        self.assertEqual(_u64(image, 0x90), 0)
        self.assertEqual(image[0x98], 0)
        self.assertEqual(_u64(image, 0xA8), m.THIS_BASE + 0xB8)
        self.assertEqual(_u64(image, 0xB0), 0)
        self.assertEqual(image[0xB8], 0)


class TestHostId(unittest.TestCase):
    def test_default_is_hostname_literal(self):
        result = m.construct_db_options()
        self.assertEqual(result["fields"]["db_host_id"], b"__hostname__")
        self.assertEqual(result["host_id_kind"], "sso")
        image = result["image"]
        self.assertEqual(_u64(image, 0x250), m.THIS_BASE + 0x260)
        self.assertEqual(_u64(image, 0x258), 12)
        self.assertEqual(image[0x260:0x26C], b"__hostname__")
        self.assertEqual(image[0x26C], 0)

    def test_sso_boundary_15(self):
        result = m.construct_db_options(host_id=b"0123456789abcde")
        self.assertEqual(result["host_id_kind"], "sso")
        self.assertEqual(_u64(result["image"], 0x258), 15)

    def test_heap_boundary_16(self):
        result = m.construct_db_options(host_id=b"0123456789abcdef")
        self.assertEqual(result["host_id_kind"], "heap")
        image = result["image"]
        self.assertEqual(_u64(image, 0x258), 16)
        self.assertEqual(_u64(image, 0x260), 16)  # capacity
        self.assertNotEqual(_u64(image, 0x250), m.THIS_BASE + 0x260)

    def test_empty_host_id(self):
        result = m.construct_db_options(host_id=b"")
        self.assertEqual(result["host_id_kind"], "sso")
        self.assertEqual(_u64(result["image"], 0x258), 0)
        self.assertEqual(result["image"][0x260], 0)

    def test_heap_id_deterministic(self):
        a = m.construct_db_options(host_id=b"0123456789abcdef")
        b = m.construct_db_options(host_id=b"0123456789abcdef")
        self.assertEqual(a["image"], b["image"])
        c = m.construct_db_options(host_id=b"0123456789abcdeg")
        self.assertNotEqual(a["image"], c["image"])

    def test_env_id_only_moves_env_slot(self):
        a = m.construct_db_options(env_id=0)["image"]
        b = m.construct_db_options(env_id=0x1234)["image"]
        self.assertEqual(_u64(b, 0x08), 0x1234)
        self.assertEqual(a[:0x08] + a[0x10:], b[:0x08] + b[0x10:])


class TestThrowPaths(unittest.TestCase):
    def test_null_host_id_throws_logic_error(self):
        with self.assertRaises(m.LogicError) as ctx:
            m.construct_db_options(host_id=None)
        self.assertEqual(str(ctx.exception), m.LOGIC_ERROR_MSG)
        self.assertEqual(ctx.exception.destroyed, m.COLD_DESTROYED)

    def test_alloc_failure_throws_bad_alloc(self):
        with self.assertRaises(m.BadAlloc) as ctx:
            m.construct_db_options(host_id=b"x" * 32, fail_alloc=True)
        self.assertEqual(ctx.exception.destroyed, m.COLD_DESTROYED)

    def test_short_host_id_never_alloc_fails(self):
        result = m.construct_db_options(host_id=b"short", fail_alloc=True)
        self.assertEqual(result["host_id_kind"], "sso")

    def test_cold_destroyed_order(self):
        # Reverse declaration order of the members constructed before
        # the guarded db_host_id region; matches the .cold FDE.
        self.assertEqual(m.COLD_DESTROYED, [
            "file_checksum_gen_factory", "row_cache", "listeners",
            "write_buffer_manager", "wal_dir", "db_log_dir", "db_paths",
            "statistics", "info_log", "sst_file_manager", "rate_limiter",
        ])
        self.assertEqual(len(m.COLD_DESTROYED), 11)


class TestImage(unittest.TestCase):
    def test_image_hash_stable(self):
        a = m.image_sha256()
        b = m.image_sha256()
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_padding_modelled_zero(self):
        image = _img(m.construct_db_options())
        # Padding the ctor never writes is modelled as zero.
        for off in (0x07, 0x41, 0x42, 0x43, 0x4C, 0x4D, 0x4E, 0x4F,
                    0x5F, 0x67, 0x6F, 0x7F, 0x87, 0x97, 0xA7, 0xB7,
                    0xC7, 0xCF, 0xEF, 0xFF, 0x107, 0x10F, 0x11F,
                    0x127, 0x12E, 0x12F, 0x137, 0x13F, 0x147, 0x14F,
                    0x157, 0x167, 0x16F, 0x177, 0x17F, 0x187, 0x18F,
                    0x197, 0x19F, 0x1BF, 0x1C7, 0x1CF, 0x1D7, 0x1DF,
                    0x1E7, 0x1EF, 0x1F7, 0x207, 0x20F, 0x21F, 0x227,
                    0x237, 0x23B, 0x247, 0x24F, 0x26F, 0x277,
                    0x287, 0x28A):
            self.assertEqual(image[off], 0, hex(off))

    def test_callers(self):
        self.assertEqual(len(m.CALLERS), 11)
        sites = [s for s, _f, _n in m.CALLERS]
        self.assertIn(0x60C2E37, sites)  # BuildDBOptions
        self.assertEqual(len(set(sites)), 11)


if __name__ == "__main__":
    unittest.main()
