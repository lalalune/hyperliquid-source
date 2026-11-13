#!/usr/bin/env python3
"""Tests for tools/db_options_options_ctor115.py.

Every value asserted here is pinned by the node #115 disassembly of
rocksdb::DBOptions::DBOptions(const Options&) (0x60b3280..0x60b3b87,
main FDE) and its .cold landing-pad FDE (0x60b3154..0x60b327a), and
cross-checked against upstream RocksDB v8.1.1
include/rocksdb/options.h:447,967,969 (DBOptions declares only
DBOptions() and explicit DBOptions(const Options&); struct Options
inherits DBOptions first at :1399, so the DBOptions subobject is at
Options+0x00) and options/options.cc:128-130 (the source delegates
to the copy ctor, but the binary inlines the memberwise copy --
no call to the copy ctor 0x5d38750 exists in this FDE).
"""

import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import db_options_options_ctor115 as m


def _img(result):
    return result["image"]


def _u64(image, off):
    return struct.unpack_from("<Q", image, off)[0]


def _i32(image, off):
    return struct.unpack_from("<i", image, off)[0]


def _src(**overrides):
    fields = m.default_fields()
    fields.update(overrides)
    return fields


def _copy(**overrides):
    return m.copy_db_options(_src(**overrides))


class TestCopyBasics(unittest.TestCase):
    def test_size_and_field_count(self):
        result = _copy()
        self.assertEqual(len(result["image"]), 0x290)
        self.assertEqual(len(result["fields"]), 93)
        self.assertEqual(len(m.FIELDS), 93)
        self.assertIsNone(result["destroyed"])

    def test_copy_of_defaults_is_defaults(self):
        # All SSO/empty/null in the default image, so the copy is
        # byte-identical to the #6337 default image.
        result = _copy()
        default_image, _h = m.build_image(m.default_fields(), "src")
        self.assertEqual(result["image"], default_image)
        self.assertEqual(result["image_sha256"],
                         "ea59a732051f16d90fc6be9592a41045d12fd8786ba1a215acefb9fbd6c94533")

    def test_copy_is_deterministic(self):
        a = _copy(max_open_files=42, db_log_dir=b"/var/log/db-long-dir")
        b = _copy(max_open_files=42, db_log_dir=b"/var/log/db-long-dir")
        self.assertEqual(a["image"], b["image"])
        self.assertEqual(a["image_sha256"], b["image_sha256"])
        self.assertEqual(a["heap"], b["heap"])

    def test_source_is_not_mutated(self):
        src = _src(max_open_files=7)
        before = m.build_image(src, "src")[0]
        _copy(max_open_files=7)
        self.assertEqual(m.build_image(src, "src")[0], before)


class TestScalars(unittest.TestCase):
    def test_bool_and_numeric_fields_copied(self):
        result = _copy(create_if_missing=True, paranoid_checks=False,
                       info_log_level=4, max_open_files=-42,
                       max_file_opening_threads=3,
                       delete_obsolete_files_period_micros=123456789,
                       max_background_jobs=9, max_subcompactions=5,
                       table_cache_numshardbits=2,
                       stats_dump_period_sec=30,
                       stats_history_buffer_size=777,
                       wal_recovery_mode=0, wal_compression=2,
                       max_bgerror_resume_count=-5,
                       lowest_used_cache_tier=0)
        f = result["fields"]
        self.assertIs(f["create_if_missing"], True)
        self.assertIs(f["paranoid_checks"], False)
        self.assertEqual(f["info_log_level"], 4)
        self.assertEqual(f["max_open_files"], -42)
        self.assertEqual(f["max_file_opening_threads"], 3)
        self.assertEqual(f["delete_obsolete_files_period_micros"], 123456789)
        self.assertEqual(f["max_background_jobs"], 9)
        self.assertEqual(f["max_subcompactions"], 5)
        self.assertEqual(f["table_cache_numshardbits"], 2)
        self.assertEqual(f["stats_dump_period_sec"], 30)
        self.assertEqual(f["stats_history_buffer_size"], 777)
        self.assertEqual(f["wal_recovery_mode"], 0)
        self.assertEqual(f["wal_compression"], 2)
        self.assertEqual(f["max_bgerror_resume_count"], -5)
        self.assertEqual(f["lowest_used_cache_tier"], 0)

    def test_packed_bool_quads_copied(self):
        # The binary copies the bool quads as one u32/u16 each.
        result = _copy(allow_mmap_reads=True, use_direct_reads=True,
                       enable_pipelined_write=True, unordered_write=True,
                       skip_stats_update_on_db_open=True, allow_2pc=True,
                       atomic_flush=True, avoid_unnecessary_blocking_io=True)
        image = result["image"]
        # allow_mmap_reads=1, allow_mmap_writes=0, use_direct_reads=1,
        # use_direct_io_for_flush_and_compaction=0.
        self.assertEqual(struct.unpack_from("<I", image, 0x128)[0], 0x00010001)
        self.assertEqual(struct.unpack_from("<I", image, 0x1D0)[0],
                         0x01010101)
        # skip_stats=1, skip_checking=0, wal_recovery_mode=2, allow_2pc=1.
        self.assertEqual(struct.unpack_from("<I", image, 0x1F0)[0],
                         0x01020001)
        # atomic_flush=1, avoid_unnecessary_blocking_io=1: two bool bytes.
        self.assertEqual(struct.unpack_from("<H", image, 0x218)[0], 0x0101)

    def test_env_and_wal_filter_are_raw_pointer_copies(self):
        result = _copy(env=0x7F0000001000, wal_filter=0x5000)
        self.assertEqual(_u64(result["image"], 0x08), 0x7F0000001000)
        self.assertEqual(_u64(result["image"], 0x208), 0x5000)
        self.assertEqual(result["fields"]["env"], 0x7F0000001000)
        self.assertEqual(result["fields"]["wal_filter"], 0x5000)

    def test_only_env_slot_moves(self):
        a = _copy(env=0)["image"]
        b = _copy(env=0x1234)["image"]
        self.assertEqual(a[:0x08] + a[0x10:], b[:0x08] + b[0x10:])


class TestSharedPointers(unittest.TestCase):
    def test_shared_ptr_shares_ctrl_and_bumps_refcount(self):
        src = m._shared(0x3000, 0x4000, 2)
        result = _copy(rate_limiter=src, statistics=m._shared(0x3010, 0x4010, 1))
        f = result["fields"]
        self.assertEqual(f["rate_limiter"],
                         {"obj": 0x3000, "ctrl": 0x4000, "refcount": 3})
        self.assertEqual(f["statistics"],
                         {"obj": 0x3010, "ctrl": 0x4010, "refcount": 2})
        # Same ctrl id in the image (shared, not deep-copied).
        self.assertEqual(_u64(result["image"], 0x10), 0x3000)
        self.assertEqual(_u64(result["image"], 0x18), 0x4000)
        self.assertEqual(_u64(result["image"], 0x58), 0x3010)
        self.assertEqual(_u64(result["image"], 0x60), 0x4010)

    def test_all_eight_shared_fields(self):
        overrides = {name: m._shared(0x3000 + i * 0x10, 0x4000 + i * 0x10, 1)
                     for i, name in enumerate(m.SHARED_PTR_FIELDS)}
        result = _copy(**overrides)
        for i, name in enumerate(m.SHARED_PTR_FIELDS):
            got = result["fields"][name]
            self.assertEqual(got["obj"], 0x3000 + i * 0x10, name)
            self.assertEqual(got["ctrl"], 0x4000 + i * 0x10, name)
            self.assertEqual(got["refcount"], 2, name)

    def test_null_shared_ptr_stays_null(self):
        result = _copy()
        image = result["image"]
        for off in (0x10, 0x20, 0x30, 0x58, 0x158, 0x1F8, 0x228, 0x278):
            self.assertEqual(image[off:off + 16], b"\0" * 16, hex(off))


class TestStrings(unittest.TestCase):
    def test_sso_string_deep_copied_same_bytes(self):
        result = _copy(db_log_dir=b"short", wal_dir=b"abc",
                       db_host_id=b"node-115")
        f = result["fields"]
        self.assertEqual(f["db_log_dir"], b"short")
        self.assertEqual(f["wal_dir"], b"abc")
        self.assertEqual(f["db_host_id"], b"node-115")
        image = result["image"]
        self.assertEqual(_u64(image, 0x88), m.THIS_BASE + 0x98)
        self.assertEqual(_u64(image, 0x90), 5)
        self.assertEqual(image[0x98:0x9D], b"short")
        self.assertEqual(image[0x9D], 0)

    def test_heap_string_gets_fresh_heap_id(self):
        src = _src(db_log_dir=b"0123456789abcdef")
        src_image, src_heap = m.build_image(src, "src")
        result = _copy(db_log_dir=b"0123456789abcdef")
        self.assertEqual(result["fields"]["db_log_dir"],
                         b"0123456789abcdef")
        src_ptr = _u64(src_image, 0x88)
        dst_ptr = _u64(result["image"], 0x88)
        self.assertNotEqual(src_ptr, dst_ptr)
        self.assertEqual(_u64(result["image"], 0x90), 16)
        self.assertEqual(_u64(result["image"], 0x98), 16)  # capacity
        self.assertIn(dst_ptr, result["heap"])
        self.assertEqual(result["heap"][dst_ptr], b"0123456789abcdef")

    def test_sso_heap_boundary(self):
        sso = _copy(db_host_id=b"0123456789abcde")
        self.assertEqual(_u64(sso["image"], 0x250), m.THIS_BASE + 0x260)
        self.assertEqual(_u64(sso["image"], 0x258), 15)
        heap = _copy(db_host_id=b"0123456789abcdef")
        self.assertNotEqual(_u64(heap["image"], 0x250), m.THIS_BASE + 0x260)
        self.assertEqual(_u64(heap["image"], 0x258), 16)
        self.assertEqual(_u64(heap["image"], 0x260), 16)


class TestVectors(unittest.TestCase):
    def test_empty_vectors_stay_zeroed(self):
        result = _copy()
        image = result["image"]
        self.assertEqual(image[0x70:0x88], b"\0" * 24)
        self.assertEqual(image[0x1A8:0x1C0], b"\0" * 24)

    def test_db_paths_deep_copied_with_exact_capacity(self):
        paths = [{"path": b"/data/db1", "target_size": 1 << 30},
                 {"path": b"0123456789abcdefg", "target_size": 5}]
        src = _src(db_paths=paths)
        src_image, _h = m.build_image(src, "src")
        result = _copy(db_paths=paths)
        self.assertEqual(result["fields"]["db_paths"], paths)
        src_begin = _u64(src_image, 0x70)
        dst_begin = _u64(result["image"], 0x70)
        self.assertNotEqual(src_begin, dst_begin)
        # cap == end == begin + 2 * 0x28: exact allocation, no slack.
        self.assertEqual(_u64(result["image"], 0x78), dst_begin + 0x50)
        self.assertEqual(_u64(result["image"], 0x80), dst_begin + 0x50)
        # Heap element bytes: path strings + target sizes.
        heap_elems = result["heap"][dst_begin]
        self.assertEqual(len(heap_elems), 0x50)
        self.assertEqual(heap_elems[0x20:0x28],
                         struct.pack("<Q", 1 << 30))
        self.assertEqual(heap_elems[0x48:0x50], struct.pack("<Q", 5))

    def test_dbpath_sso_pointer_is_inside_vector_buffer(self):
        paths = [{"path": b"short", "target_size": 0}]
        result = _copy(db_paths=paths)
        begin = _u64(result["image"], 0x70)
        elems = result["heap"][begin]
        # Element 0 string SSO ptr = begin + 0x10 (element + 16).
        self.assertEqual(struct.unpack_from("<Q", elems, 0)[0], begin + 0x10)
        self.assertEqual(elems[0x10:0x15], b"short")
        self.assertEqual(elems[0x15], 0)

    def test_dbpath_long_path_gets_own_heap_buffer(self):
        paths = [{"path": b"0123456789abcdefg", "target_size": 3}]
        result = _copy(db_paths=paths)
        begin = _u64(result["image"], 0x70)
        elems = result["heap"][begin]
        ptr = struct.unpack_from("<Q", elems, 0)[0]
        self.assertIn(ptr, result["heap"])
        self.assertEqual(result["heap"][ptr], b"0123456789abcdefg")
        self.assertEqual(struct.unpack_from("<Q", elems, 8)[0], 17)
        self.assertEqual(struct.unpack_from("<Q", elems, 0x10)[0], 17)

    def test_listeners_shared_not_deep_copied(self):
        listeners = [m._shared(0x3100, 0x4100, 1),
                     m._shared(0x3200, 0x4200, 3)]
        src = _src(listeners=listeners)
        src_image, _h = m.build_image(src, "src")
        result = _copy(listeners=listeners)
        self.assertEqual(result["fields"]["listeners"], [
            {"obj": 0x3100, "ctrl": 0x4100, "refcount": 2},
            {"obj": 0x3200, "ctrl": 0x4200, "refcount": 4},
        ])
        src_begin = _u64(src_image, 0x1A8)
        dst_begin = _u64(result["image"], 0x1A8)
        self.assertNotEqual(src_begin, dst_begin)
        self.assertEqual(_u64(result["image"], 0x1B0), dst_begin + 0x20)
        self.assertEqual(_u64(result["image"], 0x1B8), dst_begin + 0x20)
        elems = result["heap"][dst_begin]
        self.assertEqual(struct.unpack_from("<QQ", elems, 0),
                         (0x3100, 0x4100))
        self.assertEqual(struct.unpack_from("<QQ", elems, 0x10),
                         (0x3200, 0x4200))


class TestThrowPaths(unittest.TestCase):
    def _expect_throw(self, fail_at, exc_type, **overrides):
        src = _src(**overrides)
        with self.assertRaises(exc_type) as ctx:
            m.copy_db_options(src, fail_at=fail_at,
                              fail_index=1 if fail_at == "db_paths_copy"
                              else None)
        return ctx.exception

    def test_db_paths_new(self):
        err = self._expect_throw("db_paths_new", m.BadAlloc,
                                 db_paths=[{"path": b"x", "target_size": 0}])
        self.assertEqual(err.destroyed,
                         ["statistics", "info_log", "sst_file_manager",
                          "rate_limiter"])

    def test_db_paths_length(self):
        err = self._expect_throw("db_paths_length", m.BadArrayNewLength)
        self.assertEqual(err.destroyed,
                         ["statistics", "info_log", "sst_file_manager",
                          "rate_limiter"])

    def test_db_paths_copy_disposes_prefix(self):
        paths = [{"path": b"0123456789abcdefg", "target_size": 9},
                 {"path": b"s", "target_size": 1},
                 {"path": b"0123456789abcdef0123456789abcdef",
                  "target_size": 2}]
        err = self._expect_throw("db_paths_copy", m.BadAlloc,
                                 db_paths=paths)
        self.assertEqual(err.prefix_disposed, 1)
        self.assertEqual(err.destroyed,
                         ["db_paths:buffer", "statistics", "info_log",
                          "sst_file_manager", "rate_limiter"])

    def test_db_log_dir(self):
        err = self._expect_throw("db_log_dir", m.BadAlloc,
                                 db_log_dir=b"0123456789abcdef")
        self.assertEqual(err.destroyed,
                         ["db_paths", "statistics", "info_log",
                          "sst_file_manager", "rate_limiter"])

    def test_wal_dir(self):
        err = self._expect_throw("wal_dir", m.BadAlloc,
                                 wal_dir=b"0123456789abcdef")
        self.assertEqual(err.destroyed,
                         ["db_log_dir", "db_paths", "statistics", "info_log",
                          "sst_file_manager", "rate_limiter"])

    def test_listeners_new(self):
        err = self._expect_throw("listeners_new", m.BadAlloc,
                                 listeners=[m._shared(0x3100, 0x4100, 1)])
        self.assertEqual(err.destroyed,
                         ["write_buffer_manager", "wal_dir", "db_log_dir",
                          "db_paths", "statistics", "info_log",
                          "sst_file_manager", "rate_limiter"])

    def test_listeners_length(self):
        err = self._expect_throw("listeners_length", m.BadArrayNewLength)
        self.assertEqual(err.destroyed,
                         ["write_buffer_manager", "wal_dir", "db_log_dir",
                          "db_paths", "statistics", "info_log",
                          "sst_file_manager", "rate_limiter"])

    def test_db_host_id(self):
        err = self._expect_throw("db_host_id", m.BadAlloc,
                                 db_host_id=b"0123456789abcdef")
        self.assertEqual(err.destroyed,
                         ["file_checksum_gen_factory", "row_cache",
                          "listeners", "write_buffer_manager", "wal_dir",
                          "db_log_dir", "db_paths", "statistics", "info_log",
                          "sst_file_manager", "rate_limiter"])

    def test_pad_destroyed_table_matches_lsda(self):
        self.assertEqual(len(m.PAD_DESTROYED), 8)
        for name, destroyed in m.PAD_DESTROYED.items():
            # Every pad ends with the same 4-member chain.
            self.assertEqual(destroyed[-4:], m.PAD_CHAIN, name)


class TestBindings(unittest.TestCase):
    def test_callers(self):
        self.assertEqual(len(m.CALLERS), 6)
        sites = [s for s, _f, _n in m.CALLERS]
        self.assertIn(0x5D396FF, sites)  # C API optimistic open
        self.assertIn(0x5E65578, sites)  # DB::Open
        self.assertIn(0x5E73442, sites)  # DB::OpenForReadOnly
        self.assertIn(0x5E79D2E, sites)  # CompactedDBImpl::Open
        self.assertIn(0x5E81F5A, sites)  # DB::OpenAsSecondary
        self.assertIn(0x6207796, sites)  # DBWithTTL::Open
        self.assertEqual(len(set(sites)), 6)

    def test_copy_result_independent_of_caller(self):
        a = _copy(db_host_id=b"node-115", env=0x1000)
        b = _copy(db_host_id=b"node-115", env=0x1000)
        self.assertEqual(a["image_sha256"], b["image_sha256"])

    def test_constants(self):
        self.assertEqual(m.CTOR_START, 0x60B3280)
        self.assertEqual(m.CTOR_END, 0x60B3B87)
        self.assertEqual(m.CTOR_END - m.CTOR_START, 2311)
        self.assertEqual(m.CTOR_BODY_SHA256,
                         "7c4707c22eeabfb1ed1d4db475347822af6d2a6bbc6708d3242101d5b4a275c2")
        self.assertEqual(m.CTOR_SOURCE_SHA256,
                         "e9bc1ce7a303f7ba21595e4b95abd2edfb009864f03ef9d0072e322674d6eccd")
        self.assertEqual(m.COLD_START, 0x60B3154)
        self.assertEqual(m.COLD_END, 0x60B327A)
        self.assertEqual(m.COLD_END - m.COLD_START, 294)
        self.assertEqual(m.COLD_BODY_SHA256,
                         "f1428783628f1a3844ebb2aadf27fa2d7b07401cab672da980b7c6ec32f6155e")
        self.assertEqual(m.COLD_SOURCE_SHA256,
                         "de25ebd703442d1fed35a68fe665eb1c546f9555a4f5cdb8633959601ea0684c")
        self.assertEqual(m.LSDA_VA, 0x422440)
        self.assertEqual(m.COLD_LSDA_VA, 0x42247c)


if __name__ == "__main__":
    unittest.main()
