#!/usr/bin/env python3
"""Tests for tools/check_compression_supported115.py.

Every value asserted here is pinned by the node #115 disassembly of
rocksdb::CheckCompressionSupported (0x5d8dcc0..0x5d8e356, 1686 B,
main FDE) plus its .cold FDE (0x5d8dc2c..0x5d8dcb5, 137 B), the
Status ctor at 0x61cf670, ZSTD_versionNumber at 0x620dd50 (returns
10506) and CompressionTypeToString at 0x5d8b3c0, and cross-checked
against upstream RocksDB v8.1.1 db/column_family.cc:113-159 (read
live) and util/compression.h:547-571, 1435-1440, 1495-1498 (the
CompressionTypeSupported switch and the ZSTD version gates).
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import check_compression_supported115 as m


def _cf(**overrides):
    opts = m.default_cf_options()
    opts.update(overrides)
    return opts


def _opts(train=0, trainer=True, max_dict=0):
    return {"zstd_max_train_bytes": train,
            "use_zstd_dict_trainer": trainer,
            "max_dict_bytes": max_dict}


class StatusLayoutTest(unittest.TestCase):
    def test_ok_image_is_all_zero(self):
        st = m.Status.ok()
        self.assertEqual(st.image(), bytes(16))
        self.assertTrue(st.is_ok())

    def test_error_image_byte_layout(self):
        # The ctor proves the byte layout: code u8 +0x0, subcode u8
        # +0x1, severity u8 +0x2, padding +0x3..+0x7, state_ +0x8.
        st = m.Status.error("kInvalidArgument",
                            "zstd finalizeDictionary cannot be used "
                            "because ZSTD 1.4.5+ is not linked with the "
                            "binary.")
        img = st.image()
        self.assertEqual(img[0], 4)          # code byte
        self.assertEqual(img[1], 0)          # subcode byte
        self.assertEqual(img[2], 0)          # severity byte
        self.assertEqual(img[3:8], b"\x00" * 5)  # padding never written
        self.assertNotEqual(struct.unpack_from("<Q", img, 8)[0], 0)

    def test_state_buffer_is_msg_plus_nul(self):
        msg = m.MESSAGES["trainer"][0]
        st = m.status_ctor(m.CODE["kInvalidArgument"], msg, "")
        self.assertEqual(st.state_buffer(), msg.encode() + b"\x00")
        self.assertEqual(st.state_alloc(), 89 + 1)

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


class CompressionTypeSupportedTest(unittest.TestCase):
    def test_linked_types_pass(self):
        for value in (0, 1, 2, 3, 4, 5, 0x40):
            self.assertTrue(
                m.compression_type_supported(value, 10506),
                "value 0x%x should be supported" % value)

    def test_xpress_is_not_linked(self):
        self.assertFalse(m.compression_type_supported(6, 10506))

    def test_unknown_bytes_are_not_linked(self):
        for value in (8, 9, 0x3F, 0x41, 0xFE, 0xFF):
            self.assertFalse(
                m.compression_type_supported(value, 10506),
                "value 0x%x should fail" % value)

    def test_zstd_version_gate(self):
        self.assertFalse(m.compression_type_supported(7, 799))
        self.assertTrue(m.compression_type_supported(7, 800))
        self.assertTrue(m.compression_type_supported(7, 10506))

    def test_names(self):
        self.assertEqual(m.compression_type_to_string(0), "NoCompression")
        self.assertEqual(m.compression_type_to_string(1), "Snappy")
        self.assertEqual(m.compression_type_to_string(7), "ZSTD")
        self.assertEqual(m.compression_type_to_string(0x40),
                         "ZSTDNotFinal")
        self.assertEqual(m.compression_type_to_string(0xFF),
                         "DisableOption")
        self.assertEqual(m.compression_type_to_string(8), "")
        self.assertEqual(m.compression_type_to_string(9), "")


class ChecksTest(unittest.TestCase):
    def test_defaults_ok(self):
        self.assertTrue(m.check_compression_supported(_cf()).is_ok())

    def test_per_level_xpress_fails(self):
        st = m.check_compression_supported(
            _cf(compression_per_level=[0, 1, 6]))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "Compression type Xpress is not linked with the binary.")

    def test_per_level_first_bad_byte_wins(self):
        st = m.check_compression_supported(
            _cf(compression_per_level=[6, 8]))
        self.assertEqual(
            st.state,
            "Compression type Xpress is not linked with the binary.")
        st = m.check_compression_supported(
            _cf(compression_per_level=[8, 6]))
        self.assertEqual(
            st.state,
            "Compression type  is not linked with the binary.")

    def test_per_level_empty_name_for_byte_8(self):
        st = m.check_compression_supported(_cf(compression_per_level=[8]))
        self.assertEqual(
            st.state,
            "Compression type  is not linked with the binary.")

    def test_per_level_disable_option_names_it(self):
        st = m.check_compression_supported(
            _cf(compression_per_level=[0xFF]))
        self.assertEqual(
            st.state,
            "Compression type DisableOption is not linked with the "
            "binary.")

    def test_empty_vector_uses_single_compression(self):
        # The else branch (0x5d8e130) reads compression +0x220.
        st = m.check_compression_supported(
            _cf(compression_per_level=[], compression=6))
        self.assertEqual(
            st.state,
            "Compression type Xpress is not linked with the binary.")
        self.assertTrue(m.check_compression_supported(
            _cf(compression_per_level=[], compression=0x40)).is_ok())

    def test_per_level_masks_single_compression(self):
        # A non-empty vector never reaches the else branch.
        st = m.check_compression_supported(
            _cf(compression_per_level=[6], compression=6))
        self.assertEqual(
            st.state,
            "Compression type Xpress is not linked with the binary.")

    def test_trainer_gate(self):
        cf = _cf(compression_opts=_opts(train=1, trainer=True,
                                        max_dict=1),
                 zstd_version=10102)
        st = m.check_compression_supported(cf)
        self.assertEqual(st.state, m.MESSAGES["trainer"][0])
        cf = _cf(compression_opts=_opts(train=1, trainer=True,
                                        max_dict=1),
                 zstd_version=10103)
        self.assertTrue(m.check_compression_supported(cf).is_ok())

    def test_finalize_gate(self):
        cf = _cf(compression_opts=_opts(train=1, trainer=False,
                                        max_dict=1),
                 zstd_version=10404)
        st = m.check_compression_supported(cf)
        self.assertEqual(st.state, m.MESSAGES["finalize"][0])
        cf = _cf(compression_opts=_opts(train=1, trainer=False,
                                        max_dict=1),
                 zstd_version=10405)
        self.assertTrue(m.check_compression_supported(cf).is_ok())

    def test_trainer_gate_masks_max_dict_gate(self):
        cf = _cf(compression_opts=_opts(train=1, trainer=True,
                                        max_dict=0),
                 zstd_version=10102)
        st = m.check_compression_supported(cf)
        self.assertEqual(st.state, m.MESSAGES["trainer"][0])

    def test_max_dict_bytes_must_be_nonzero(self):
        cf = _cf(compression_opts=_opts(train=1, trainer=False,
                                        max_dict=0))
        st = m.check_compression_supported(cf)
        self.assertEqual(st.state, m.MESSAGES["max_dict"][0])

    def test_train_bytes_zero_skips_zstd_gates(self):
        cf = _cf(compression_opts=_opts(train=0, trainer=True,
                                        max_dict=0),
                 zstd_version=799)
        self.assertTrue(m.check_compression_supported(cf).is_ok())

    def test_blob_compression_type(self):
        st = m.check_compression_supported(_cf(blob_compression_type=6))
        self.assertEqual(st.code, 4)
        self.assertEqual(
            st.state,
            "The specified blob compression type Xpress is not "
            "available.")
        self.assertTrue(m.check_compression_supported(
            _cf(blob_compression_type=0x40)).is_ok())
        st = m.check_compression_supported(_cf(blob_compression_type=8))
        self.assertEqual(
            st.state,
            "The specified blob compression type  is not available.")

    def test_first_failure_wins(self):
        cf = _cf(compression_per_level=[6],
                 compression_opts=_opts(train=1, trainer=True,
                                       max_dict=0),
                 zstd_version=10102, blob_compression_type=6)
        st = m.check_compression_supported(cf)
        self.assertEqual(
            st.state,
            "Compression type Xpress is not linked with the binary.")


class ThrowTest(unittest.TestCase):
    def test_bad_alloc_in_per_level_status_ctor(self):
        with self.assertRaises(m.BadAlloc) as ctx:
            m.check_compression_supported(
                _cf(compression_per_level=[6]),
                fail_at="status-ctor:per-level")
        err = ctx.exception
        self.assertEqual(err.site, 0x5D8DDD1)
        self.assertEqual(err.pad, 0x65A)
        self.assertEqual(err.cleanup, ["dispose_r13_string",
                                       "dispose_rbx_string",
                                       "dispose_rbp_string"])
        self.assertEqual(err.partial.code, 4)
        self.assertIsNone(err.partial.state)

    def test_bad_alloc_in_max_dict_status_ctor_has_no_cleanup(self):
        # Pad 0: the max_dict/trainer/finalize ctor has no live
        # strings to clean up (plain .rodata message).
        with self.assertRaises(m.BadAlloc) as ctx:
            m.check_compression_supported(
                _cf(compression_opts=_opts(train=1, trainer=False,
                                           max_dict=0)),
                fail_at="status-ctor:max-dict")
        err = ctx.exception
        self.assertEqual(err.site, 0x5D8DEC1)
        self.assertEqual(err.pad, 0x000)
        self.assertEqual(err.cleanup, [])

    def test_callee_throw_in_blob_ostream_insert(self):
        with self.assertRaises(m.CalleeThrow) as ctx:
            m.check_compression_supported(
                _cf(blob_compression_type=6),
                fail_at="ostream-insert:blob-name")
        err = ctx.exception
        self.assertEqual(err.site, 0x5D8DF4F)
        self.assertEqual(err.pad, 0x642)
        self.assertEqual(err.cleanup, ["dispose_rbx_string",
                                       "destroy_ostringstream"])

    def test_single_replace_pad_disposes_all_three_slots(self):
        # The +1222 pad (0x636) disposes r13/rbx/rbp as coded,
        # even though only rbp is constructed at that site.
        with self.assertRaises(m.CalleeThrow) as ctx:
            m.check_compression_supported(
                _cf(compression_per_level=[], compression=6),
                fail_at="string-replace:single")
        err = ctx.exception
        self.assertEqual(err.site, 0x5D8E186)
        self.assertEqual(err.pad, 0x636)
        self.assertEqual(err.cleanup, ["dispose_r13_string",
                                       "dispose_rbx_string",
                                       "dispose_rbp_string"])

    def test_canary_failure_on_ok_return(self):
        with self.assertRaises(m.StackCheckFailed):
            m.check_compression_supported(_cf(), canary_ok=False)

    def test_canary_failure_on_error_return(self):
        with self.assertRaises(m.StackCheckFailed):
            m.check_compression_supported(
                _cf(compression_per_level=[6]), canary_ok=False)

    def test_throw_with_bad_canary_raises_stack_check(self):
        # The pad's canary check fires before the exception
        # resumes: BadAlloc + bad canary -> StackCheckFailed.
        with self.assertRaises(m.StackCheckFailed) as ctx:
            m.check_compression_supported(
                _cf(compression_per_level=[6]),
                fail_at="status-ctor:per-level", canary_ok=False)
        self.assertEqual(ctx.exception.site, 0x5D8DDD1)
        self.assertEqual(ctx.exception.pad, 0x65A)

    def test_alloc_ok_false_with_no_fail_at_only_fires_on_error(self):
        st = m.check_compression_supported(
            _cf(), alloc_ok=False)
        self.assertTrue(st.is_ok())
        with self.assertRaises(m.BadAlloc):
            m.check_compression_supported(
                _cf(compression_per_level=[6]), alloc_ok=False)


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
