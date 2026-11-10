#!/usr/bin/env python3
"""Tests for tools/dbimpl_validate_options_1arg115.py.

Every value asserted here is pinned by the node #115 disassembly of
rocksdb::DBImpl::ValidateOptions(const DBOptions&) (0x5e59cd0..0x5e59fd3,
771 B, a single FDE with no LSDA), the Status ctor at 0x61cf670, and
cross-checked against upstream RocksDB v8.1.1
db/db_impl/db_impl_open.cc:243-298 (the nine checks, read live) and
db/db_impl/db_impl.cc:1242 (the SetDBOptions caller, read live).
The Status ctor is an oracle here only in the sense that its body
is not reconstructed -- its observable behavior (byte layout,
state_ buffer, dead delete[]) IS pinned from its disassembly.
"""

import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import dbimpl_validate_options_1arg115 as m


def _db(**overrides):
    opts = m.default_db_options()
    opts.update(overrides)
    return opts


def _paths(n):
    return [{"path": "/p%d" % i, "target_size": 1} for i in range(n)]


class StatusLayoutTest(unittest.TestCase):
    def test_ok_image_is_all_zero(self):
        st = m.Status.ok()
        self.assertEqual(st.image(), bytes(16))
        self.assertTrue(st.is_ok())

    def test_error_image_byte_layout(self):
        # The ctor proves the byte layout: code u8 +0x0, subcode u8
        # +0x1, severity u8 +0x2, padding +0x3..+0x7, state_ +0x8.
        st = m.Status.error("kInvalidArgument",
                            "keep_log_file_num must be greater than 0")
        img = st.image()
        self.assertEqual(img[0], 4)          # code byte
        self.assertEqual(img[1], 0)          # subcode byte
        self.assertEqual(img[2], 0)          # severity byte
        self.assertEqual(img[3:8], b"\x00" * 5)  # padding never written
        self.assertNotEqual(struct.unpack_from("<Q", img, 8)[0], 0)

    def test_notsupported_code_is_3(self):
        st = m.Status.error(
            "kNotSupported",
            "More than four DB paths are not supported yet. ")
        self.assertEqual(st.image()[0], 3)
        self.assertEqual(st.image()[1:8], b"\x00" * 7)

    def test_state_buffer_is_msg_plus_nul(self):
        st = m.status_ctor(m.CODE["kInvalidArgument"],
                           "keep_log_file_num must be greater than 0", "")
        self.assertEqual(
            st.state_buffer(),
            b"keep_log_file_num must be greater than 0\x00")
        self.assertEqual(st.state_alloc(), 40 + 1)

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


class NineChecksTest(unittest.TestCase):
    def test_defaults_ok(self):
        self.assertTrue(m.validate_options(_db()).is_ok())

    def test_check1_db_paths_boundary(self):
        self.assertTrue(m.validate_options(_db(db_paths=_paths(4))).is_ok())
        st = m.validate_options(_db(db_paths=_paths(5)))
        self.assertEqual(st.code, 3)
        self.assertEqual(
            st.state, "More than four DB paths are not supported yet. ")

    def test_check1_byte_size_is_160(self):
        # 4 paths x 0x28 bytes = 160 = the 0xa0 limit, exactly OK.
        self.assertEqual(4 * m.DB_PATH_SIZE, m.DB_PATHS_BYTE_LIMIT)
        self.assertEqual(m._failing_check(_db(db_paths=_paths(4))), 0)
        self.assertEqual(m._failing_check(_db(db_paths=_paths(5))), 1)

    def test_check2_mmap_reads(self):
        st = m.validate_options(
            _db(allow_mmap_reads=True, use_direct_reads=True))
        self.assertEqual(st.code, 3)
        self.assertTrue(st.state.startswith("If memory mapped reads"))
        self.assertTrue(m.validate_options(
            _db(allow_mmap_reads=True)).is_ok())
        self.assertTrue(m.validate_options(
            _db(use_direct_reads=True)).is_ok())

    def test_check3_mmap_writes(self):
        st = m.validate_options(
            _db(allow_mmap_writes=True,
                use_direct_io_for_flush_and_compaction=True))
        self.assertEqual(st.code, 3)
        self.assertTrue(st.state.startswith("If memory mapped writes"))

    def test_check4_keep_log_zero(self):
        st = m.validate_options(_db(keep_log_file_num=0))
        self.assertEqual(st.code, 4)
        self.assertEqual(st.state,
                         "keep_log_file_num must be greater than 0")
        self.assertTrue(m.validate_options(_db(keep_log_file_num=1)).is_ok())

    def test_check5_unordered_no_concurrent(self):
        st = m.validate_options(
            _db(unordered_write=True, allow_concurrent_memtable_write=False))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "unordered_write is incompatible with "
            "!allow_concurrent_memtable_write")

    def test_check6_unordered_pipelined(self):
        st = m.validate_options(
            _db(unordered_write=True, allow_concurrent_memtable_write=True,
                enable_pipelined_write=True))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "unordered_write is incompatible with enable_pipelined_write")

    def test_check7_atomic_pipelined(self):
        st = m.validate_options(
            _db(atomic_flush=True, enable_pipelined_write=True))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "atomic_flush is incompatible with enable_pipelined_write")

    def test_check8_atomic_best_efforts(self):
        st = m.validate_options(
            _db(atomic_flush=True, best_efforts_recovery=True))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "atomic_flush is currently incompatible with "
            "best-efforts recovery")

    def test_check9_direct_io_no_buffer(self):
        st = m.validate_options(
            _db(use_direct_io_for_flush_and_compaction=True,
                writable_file_max_buffer_size=0))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "writes in direct IO require writable_file_max_buffer_size > 0")
        self.assertTrue(m.validate_options(
            _db(use_direct_io_for_flush_and_compaction=True,
                writable_file_max_buffer_size=1)).is_ok())

    def test_first_failure_wins(self):
        # Check 1 masks check 4; check 5 masks check 9.
        both = _db(db_paths=_paths(5), keep_log_file_num=0)
        self.assertEqual(m._failing_check(both), 1)
        self.assertEqual(m.validate_options(both).code, 3)
        masked = _db(unordered_write=True,
                     allow_concurrent_memtable_write=False,
                     use_direct_io_for_flush_and_compaction=True,
                     writable_file_max_buffer_size=0)
        self.assertEqual(m._failing_check(masked), 5)

    def test_check7_two_entries(self):
        # Atomic + pipelined fails whether unordered_write is set
        # (via the check-6 fall-through) or not (via 0x5e59e30).
        a = _db(atomic_flush=True, enable_pipelined_write=True)
        b = _db(atomic_flush=True, enable_pipelined_write=True,
                unordered_write=True, allow_concurrent_memtable_write=True)
        self.assertEqual(m._failing_check(a), 7)
        self.assertEqual(m._failing_check(b), 6)  # check 6 fires first

    def test_check8_reached_two_ways(self):
        # Atomic + best-efforts fails with pipelined on (via
        # 0x5e59d52 -> 0x5e59eb0) and with pipelined off (via
        # 0x5e59e3d -> 0x5e59eb0) -- check 7 passes in both.
        a = _db(atomic_flush=True, best_efforts_recovery=True)
        self.assertEqual(m._failing_check(a), 8)

    def test_all_nine_messages_are_verbatim(self):
        for n, _c, msg, _a, ln, _t in m.CHECKS:
            self.assertEqual(len(msg), ln, "check %d length" % n)
        self.assertTrue(m.MESSAGES[1].endswith(" "))
        self.assertTrue(m.MESSAGES[2].endswith(" "))
        self.assertTrue(m.MESSAGES[3].endswith(" "))


class ThrowTest(unittest.TestCase):
    def test_ctor_badalloc_at_each_check(self):
        for n, _c, _msg, _a, _l, _t in m.CHECKS:
            _m, overrides = m._CHECK_FAIL_OVERRIDES[n - 1]
            opts = _db()
            if "db_paths_count" in overrides:
                opts["db_paths"] = _paths(overrides["db_paths_count"])
            else:
                opts.update(overrides)
            with self.assertRaises(m.BadAlloc) as ctx:
                m.validate_options(opts, alloc_ok=False, fail_ctor_at=n)
            partial = ctx.exception.partial
            self.assertEqual(partial.code, m.CODE[_c])
            self.assertIsNone(partial.state)

    def test_canary_failure_on_ok_return(self):
        with self.assertRaises(m.StackCheckFailed):
            m.validate_options(_db(), canary_ok=False)

    def test_canary_failure_on_error_return(self):
        with self.assertRaises(m.StackCheckFailed):
            m.validate_options(_db(keep_log_file_num=0), canary_ok=False)

    def test_throw_beats_canary(self):
        # A ctor throw never reaches the epilogue, so the canary
        # check does not run and does not mask the BadAlloc.
        with self.assertRaises(m.BadAlloc):
            m.validate_options(_db(keep_log_file_num=0), canary_ok=False,
                               alloc_ok=False, fail_ctor_at=4)


class BindingsTest(unittest.TestCase):
    def test_hashes(self):
        self.assertEqual(
            m.BODY_SHA256,
            "fe207dc0945912c63ccf42fee9aec9147a2969a5c005339aee8d9c31f6f221a2")
        self.assertEqual(
            m.SOURCE_SHA256,
            "858395f2ce9f424c05ca9a0adf90f25390883c15b38f40fe7389af759e4c47e6")
        self.assertEqual(m.START, 0x5E59CD0)
        self.assertEqual(m.END, 0x5E59FD3)
        self.assertEqual(m.END - m.START, 771)

    def test_callers(self):
        self.assertEqual(len(m.CALLERS), 2)
        self.assertEqual(m.CALLERS[0][0], 0x5E5A0EE)  # dispatcher
        self.assertEqual(m.CALLERS[1][0], 0x5D7256D)  # SetDBOptions

    def test_no_lsda(self):
        self.assertEqual(m.FDE_AUG_LEN, 0)

    def test_result_independent_of_caller(self):
        a = m.run_case({"group": "bindings", "caller_site": "0x5e5a0ee",
                        "db_overrides": {"keep_log_file_num": 0}})
        b = m.run_case({"group": "bindings", "caller_site": "0x5d7256d",
                        "db_overrides": {"keep_log_file_num": 0}})
        self.assertEqual(a["result"], b["result"])
        self.assertEqual(a["result_sha256"], b["result_sha256"])


if __name__ == "__main__":
    unittest.main()
