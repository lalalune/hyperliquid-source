#!/usr/bin/env python3
"""Tests for tools/check_concurrent_writes_supported115.py.

Every value asserted here is pinned by the node #115 disassembly of
rocksdb::CheckConcurrentWritesSupported (0x5d8ba60..0x5d8bb48, 232 B,
single FDE, no .cold FDE, no LSDA), the Status ctor at 0x61cf670 and
the virtual IsInsertConcurrentlySupported call at vtable slot 0xa8,
and cross-checked against upstream RocksDB v8.1.1
db/column_family.cc:161-171 (read live) and
include/rocksdb/memtablerep.h:321,354 (the base and SkipListFactory
answers).
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import check_concurrent_writes_supported115 as m


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
        st = m.Status.error("kInvalidArgument",
                            "Memtable doesn't concurrent writes "
                            "(allow_concurrent_memtable_write)")
        img = st.image()
        self.assertEqual(img[0], 4)          # code byte
        self.assertEqual(img[1], 0)          # subcode byte
        self.assertEqual(img[2], 0)          # severity byte
        self.assertEqual(img[3:8], b"\x00" * 5)  # padding never written
        self.assertNotEqual(struct.unpack_from("<Q", img, 8)[0], 0)

    def test_state_buffer_is_msg_plus_nul(self):
        msg = m.MESSAGES["inplace"][0]
        st = m.status_ctor(m.CODE["kInvalidArgument"], msg, "")
        self.assertEqual(st.state_buffer(), msg.encode() + b"\x00")
        self.assertEqual(st.state_alloc(), 125 + 1)

    def test_ctor_joins_nonempty_msg2_with_colon_space(self):
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


class ChecksTest(unittest.TestCase):
    def test_defaults_ok(self):
        self.assertTrue(
            m.check_concurrent_writes_supported(_cf()).is_ok())

    def test_inplace_update_support_fails(self):
        st = m.check_concurrent_writes_supported(
            _cf(inplace_update_support=True))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "In-place memtable updates (inplace_update_support) is "
            "not compatible with concurrent writes "
            "(allow_concurrent_memtable_write)")
        self.assertEqual(len(st.state), 125)

    def test_memtable_factory_not_concurrent_fails(self):
        st = m.check_concurrent_writes_supported(
            _cf(memtable_factory_concurrent=False))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "Memtable doesn't concurrent writes "
            "(allow_concurrent_memtable_write)")
        self.assertEqual(len(st.state), 68)

    def test_check_1_masks_check_2(self):
        # With inplace on, the factory answer never matters: the
        # virtual call is never reached.
        st = m.check_concurrent_writes_supported(
            _cf(inplace_update_support=True,
                memtable_factory_concurrent=False))
        self.assertEqual(
            st.state,
            "In-place memtable updates (inplace_update_support) is "
            "not compatible with concurrent writes "
            "(allow_concurrent_memtable_write)")

    def test_factory_true_passes_when_inplace_off(self):
        self.assertTrue(m.check_concurrent_writes_supported(
            _cf(inplace_update_support=False,
                memtable_factory_concurrent=True)).is_ok())

    def test_failing_check_numbers(self):
        self.assertEqual(
            m._failing_check(_cf()), 0)
        self.assertEqual(
            m._failing_check(_cf(inplace_update_support=True)), 1)
        self.assertEqual(
            m._failing_check(_cf(memtable_factory_concurrent=False)),
            2)
        self.assertEqual(
            m._failing_check(
                _cf(inplace_update_support=True,
                    memtable_factory_concurrent=False)), 1)


class ThrowTest(unittest.TestCase):
    def test_bad_alloc_in_inplace_status_ctor(self):
        with self.assertRaises(m.BadAlloc) as ctx:
            m.check_concurrent_writes_supported(
                _cf(inplace_update_support=True),
                fail_at="status-ctor:inplace")
        err = ctx.exception
        self.assertEqual(err.site, 0x5D8BB0E)
        self.assertIsNone(err.pad)
        self.assertEqual(err.cleanup, [])
        self.assertEqual(err.partial.code, 4)
        self.assertIsNone(err.partial.state)

    def test_bad_alloc_in_memtable_status_ctor(self):
        with self.assertRaises(m.BadAlloc) as ctx:
            m.check_concurrent_writes_supported(
                _cf(memtable_factory_concurrent=False),
                fail_at="status-ctor:memtable")
        err = ctx.exception
        self.assertEqual(err.site, 0x5D8BB0E)
        self.assertIsNone(err.pad)
        self.assertEqual(err.cleanup, [])
        self.assertEqual(err.partial.code, 4)
        self.assertIsNone(err.partial.state)

    def test_both_ctor_sites_share_one_call_address(self):
        # Both error paths share the single Status ctor call at
        # 0x5d8bb0e; the two fail_at names differ only in which
        # error path reaches it.
        self.assertEqual(
            m.THROW_SITES["status-ctor:inplace"][0],
            m.THROW_SITES["status-ctor:memtable"][0])

    def test_callee_throw_at_virtual_call(self):
        with self.assertRaises(m.CalleeThrow) as ctx:
            m.check_concurrent_writes_supported(
                _cf(inplace_update_support=False),
                fail_at="virtual-call:is-insert-concurrently-supported")
        err = ctx.exception
        self.assertEqual(err.site, 0x5D8BA90)
        self.assertIsNone(err.pad)
        self.assertEqual(err.cleanup, [])

    def test_virtual_call_not_reached_when_inplace_on(self):
        # Check 1 fires first, so the virtual call never runs.
        st = m.check_concurrent_writes_supported(
            _cf(inplace_update_support=True),
            fail_at="virtual-call:is-insert-concurrently-supported")
        self.assertEqual(st.code, 4)
        self.assertEqual(len(st.state), 125)

    def test_canary_failure_on_ok_return(self):
        with self.assertRaises(m.StackCheckFailed):
            m.check_concurrent_writes_supported(_cf(), canary_ok=False)

    def test_canary_failure_on_error_return(self):
        with self.assertRaises(m.StackCheckFailed):
            m.check_concurrent_writes_supported(
                _cf(inplace_update_support=True), canary_ok=False)

    def test_throw_with_bad_canary_still_propagates_as_bad_alloc(self):
        # No LSDA means no pad canary check: BadAlloc + a bad
        # canary propagates as BadAlloc, not StackCheckFailed.
        with self.assertRaises(m.BadAlloc):
            m.check_concurrent_writes_supported(
                _cf(inplace_update_support=True),
                fail_at="status-ctor:inplace", canary_ok=False)

    def test_callee_throw_with_bad_canary_propagates(self):
        with self.assertRaises(m.CalleeThrow):
            m.check_concurrent_writes_supported(
                _cf(inplace_update_support=False),
                fail_at="virtual-call:is-insert-concurrently-supported",
                canary_ok=False)

    def test_alloc_ok_false_with_no_fail_at_only_fires_on_error(self):
        st = m.check_concurrent_writes_supported(
            _cf(), alloc_ok=False)
        self.assertTrue(st.is_ok())
        with self.assertRaises(m.BadAlloc):
            m.check_concurrent_writes_supported(
                _cf(inplace_update_support=True), alloc_ok=False)


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
