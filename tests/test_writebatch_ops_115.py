"""Tests for tools/writebatch_ops_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_writebatch_ops_115.py

Every expectation is grounded in the packet
research/work-items/RE-001-writebatch-ops-115/: the record
type bytes and flag bits come from the inner appenders'
verbatim excerpts, the error strings from the .rodata bytes
they name, and the pipeline order from the wrapper/impl/
middle excerpts.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from writebatch_ops_115 import (
    OPS, VTABLE, VTABLE_ADDR, TYPEINFO_NAME,
    OK, NOT_SUPPORTED, INVALID_ARGUMENT,
    MERGE_OPERATOR_MSG, NO_CF_HANDLE_MSG, CF_TIMESTAMP_MSG,
    TS_MISMATCH_MSG, KEY_TOO_LARGE_MSG, ENTITY_TOO_LARGE_MSG,
    Status, WriteBatch, CfResolve, put_varint32, run_operation,
    check_putentity_sizes,
)

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("check failed: %s" % label)


def test_batch_init():
    b = WriteBatch()
    check(bytes(b.rep) == b"\x00" * 12, "rep starts as 12 NUL bytes")
    check(b.sequence == 0, "sequence starts 0")
    check(b.count == 0, "count starts 0")
    check(b.flags == 0, "flags start 0")


def test_varint32():
    cases = [(0, b"\x00"), (1, b"\x01"), (127, b"\x7f"),
             (128, b"\x80\x01"), (300, b"\xac\x02"),
             (16384, b"\x80\x80\x01"), (0xFFFFFFFF, b"\xff\xff\xff\xff\x0f")]
    for value, want in cases:
        check(put_varint32(value) == want, "varint32 %d" % value)
    # Round-trip against a manual decoder.
    for value in (0, 5, 127, 128, 300, 70000, 2 ** 28, 2 ** 32 - 1):
        enc = put_varint32(value)
        got, shift = 0, 0
        for byte in enc:
            got |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        check(got == value, "varint32 round-trip %d" % value)


def test_records():
    # (op, cf_id, key, value, want type byte, want flag bit)
    cases = [
        ("put", 0, b"k", b"v", 0x01, 0x0002),
        ("put", 3, b"k", b"v", 0x05, 0x0002),
        ("delete", 0, b"k", None, 0x00, 0x0004),
        ("delete", 7, b"k", None, 0x04, 0x0004),
        ("singledelete", 0, b"k", None, 0x07, 0x0008),
        ("singledelete", 2, b"k", None, 0x08, 0x0008),
        ("merge", 0, b"k", b"v", 0x02, 0x0010),
        ("merge", 9, b"k", b"v", 0x06, 0x0010),
        ("deleterange", 0, b"a", b"b", 0x0F, 0x0200),
        ("deleterange", 1, b"a", b"b", 0x0E, 0x0200),
        ("putentity", 0, b"k", b"v", 0x16, 0x1000),
        ("putentity", 5, b"k", b"v", 0x17, 0x1000),
    ]
    for op, cf_id, key, value, want_type, want_flag in cases:
        b = WriteBatch()
        rec, path = b.append_record(op, cf_id, key, value)
        check(rec[0] == want_type, "%s type byte %#x" % (op, want_type))
        check(b.count == 1, "%s bumps count to 1" % op)
        check(b.flags == want_flag, "%s flag bit %#x" % (op, want_flag))
        check(bytes(b.rep[:12]) == b"\x00" * 8 + struct.pack("<I", 1),
              "%s rep header after one record" % op)
        check(bytes(b.rep[12:]) == rec, "%s rep holds the record" % op)
        # The CF id varint follows the type byte iff cf_id != 0.
        pos = 1
        if cf_id != 0:
            check(rec[1:2] == put_varint32(cf_id), "%s cf varint" % op)
            pos += len(put_varint32(cf_id))
        check(rec[pos:pos + 1] == put_varint32(len(key)),
              "%s key-length varint" % op)
        pos += len(put_varint32(len(key)))
        check(rec[pos:pos + len(key)] == key, "%s key bytes" % op)
        if value is not None:
            pos += len(key)
            check(rec[pos:pos + 1] == put_varint32(len(value)),
                  "%s value-length varint" % op)
        # ts_size == 0 takes the tail callee (plain key); the
        # PutEntity inner is the plain-key path too.
        check(path == "tail" if op != "putentity" else path == "inner",
              "%s ts_size 0 path" % op)
    # Two records in one batch: count 2, flags accumulate.
    b = WriteBatch()
    b.append_record("put", 0, b"k1", b"v1")
    b.append_record("delete", 0, b"k2")
    check(b.count == 2, "two records count 2")
    check(b.flags == 0x0002 | 0x0004, "flags accumulate across ops")


def test_timestamp_suffix():
    # ts_size != 0: the inner appender writes the key as key
    # bytes followed by ts_size NUL bytes (the zero timestamp
    # the middle builds); the path is "inner".
    for op, value, want_type in (("put", b"v", 0x01),
                                 ("delete", None, 0x00),
                                 ("merge", b"v", 0x02),
                                 ("deleterange", b"end", 0x0F),
                                 ("singledelete", None, 0x07)):
        b = WriteBatch()
        rec, path = b.append_record(op, 0, b"key", value, ts_size=4)
        check(path == "inner", "%s timestamped path is inner" % op)
        check(rec[0] == want_type, "%s timestamped type" % op)
        check(rec[1:2] == put_varint32(7), "%s key length 3+4" % op)
        check(rec[2:9] == b"key\x00\x00\x00\x00",
              "%s key carries the zero timestamp" % op)
        check(b.count == 1 and b.flags == OPS[op][3],
              "%s timestamped count and flag" % op)
    # A 1-byte timestamp suffix.
    b = WriteBatch()
    rec, _path = b.append_record("put", 0, b"k", b"v", ts_size=1)
    check(rec[2:4] == b"k\x00", "1-byte timestamp suffix")


def test_status_layout():
    s = Status(code=4, subcode=0, message="x")
    raw = s.to_bytes(msg_ptr=0x1234)
    check(len(raw) == 16, "Status is 16 bytes")
    check(struct.unpack_from("<H", raw, 0)[0] == 4, "code at +0x00")
    check(struct.unpack_from("<I", raw, 2)[0] == 0, "subcode at +0x02")
    check(raw[6:8] == b"\x00\x00", "+0x06..+0x07 are zero")
    check(struct.unpack_from("<Q", raw, 8)[0] == 0x1234,
          "message pointer at +0x08")
    check(Status().ok, "default Status is OK")


def test_ops_table_matches_vtable():
    # Every modelled op's middle callee sits in the WriteBatch
    # vtable at its recorded slot (RELATIVE addends at
    # 0x64cd498..); the typeinfo name is rocksdb::WriteBatch.
    check(TYPEINFO_NAME == "rocksdb::WriteBatch", "typeinfo name")
    check(VTABLE_ADDR == 0x64CD498, "vtable address")
    for op, (slot, _td, _tc, _flag, _inner) in OPS.items():
        check(slot in VTABLE, "%s slot %d in vtable" % (op, slot))
    check(VTABLE[2] == 0x5FBF5D0, "put middle at slot 2")
    check(VTABLE[7] == 0x5FC4DB0, "putentity middle at slot 7")
    check(VTABLE[8] == 0x5FC4020, "merge middle at slot 8")
    check(VTABLE[13] == 0x5FC0320, "delete middle at slot 13")
    check(VTABLE[18] == 0x5FC1010, "singledelete middle at slot 18")
    check(VTABLE[23] == 0x5FC1E60, "deleterange middle at slot 23")


def test_pipeline_success():
    seen = []

    def dispatch(db_object, batch, op):
        seen.append((db_object, bytes(batch.rep), op))
        return Status()

    for op, value in (("put", b"v"), ("delete", None),
                      ("singledelete", None), ("merge", b"v"),
                      ("deleterange", b"end"), ("putentity", b"v")):
        seen.clear()
        status, batch, _rec, path = run_operation(
            op, Status(), CfResolve(ts_size=0, cf_id=0),
            b"key", value, dispatch=dispatch)
        check(status.ok, "%s pipeline returns OK" % op)
        check(batch is not None and batch.count == 1,
              "%s pipeline appends one record" % op)
        check(len(seen) == 1 and seen[0][2] == op,
              "%s pipeline reaches the slot 0xe0 dispatch" % op)
        check(seen[0][1][12] == OPS[op][1],
              "%s dispatched batch carries its type byte" % op)
        check(path == ("inner" if op == "putentity" else "tail"),
              "%s ts_size 0 pipeline path" % op)
    # A timestamped column family: the Put middle builds the
    # zero timestamp and the inner appender writes key + 4 NULs.
    seen.clear()
    status, batch, _rec, path = run_operation(
        "put", Status(), CfResolve(ts_size=4, cf_id=0),
        b"key", b"v", dispatch=dispatch)
    check(status.ok, "timestamped put returns OK")
    check(path == "inner", "timestamped put takes the inner")
    check(bytes(batch.rep[12:]) ==
          b"\x01\x07key\x00\x00\x00\x00\x01v",
          "timestamped put record bytes")
    check(len(seen) == 1, "timestamped put still dispatches")


def test_pipeline_errors():
    # Guard non-OK: copied, no batch, no dispatch.
    seen = []
    status, batch, _rec, _path = run_operation(
        "put", Status(code=4, message="cannot call this method on "
                      "column family x that enables timestamp"),
        CfResolve(), b"k", b"v", dispatch=lambda *a: seen.append(a))
    check(status.code == 4, "guard error code copied")
    check(batch is None, "guard error builds no batch")
    check(seen == [], "guard error never dispatches")
    # Merge without a merge operator.
    status, batch, _rec, _path = run_operation(
        "merge", Status(), CfResolve(), b"k", b"v",
        merge_operator_present=False)
    check(status.code == NOT_SUPPORTED, "merge gate code 3")
    check(status.message == MERGE_OPERATOR_MSG, "merge gate message")
    check(batch is None, "merge gate builds no batch")
    # PutEntity without a column-family handle.
    status, batch, _rec, _path = run_operation(
        "putentity", Status(), None, b"k", b"v")
    check(status.code == INVALID_ARGUMENT, "no-CF-handle code 4")
    check(status.message == NO_CF_HANDLE_MSG, "no-CF-handle message")
    # PutEntity on a timestamped column family.
    status, batch, _rec, _path = run_operation(
        "putentity", Status(), CfResolve(ts_size=8), b"k", b"v")
    check(status.code == INVALID_ARGUMENT, "entity timestamp code 4")
    check(status.message == CF_TIMESTAMP_MSG, "entity timestamp message")
    # A failing CF resolution propagates.
    status, batch, _rec, _path = run_operation(
        "put", Status(),
        CfResolve(code=INVALID_ARGUMENT, message=TS_MISMATCH_MSG),
        b"k", b"v")
    check(status.code == INVALID_ARGUMENT, "resolution error code")
    check(status.message == TS_MISMATCH_MSG, "resolution error message")
    check(batch is None, "resolution error builds no batch")
    # The error strings are the verbatim .rodata literals.
    check(MERGE_OPERATOR_MSG == "Provide a merge_operator when opening DB",
          "merge literal")
    check(NO_CF_HANDLE_MSG ==
          "Cannot call this method without a column family handle",
          "no-CF literal")
    check(CF_TIMESTAMP_MSG ==
          "Cannot call this method on column family enabling timestamp",
          "CF timestamp literal")
    check(TS_MISMATCH_MSG == "Default cf timestamp size mismatch",
          "mismatch literal")
    check(KEY_TOO_LARGE_MSG == "key is too large", "key-too-large literal")
    check(ENTITY_TOO_LARGE_MSG == "wide column entity is too large",
          "entity-too-large literal")


def test_putentity_size_boundaries():
    # Both size limits are pinned at 0xFFFFFFFF in the inner
    # (cmp $0xffffffff against the key Slice length, and
    # against the entity size from 0x5fb4f60).
    check(check_putentity_sizes(0xFFFFFFFF, 0xFFFFFFFF) is None,
          "0xFFFFFFFF key and entity sizes pass")
    err = check_putentity_sizes(0x100000000, 0)
    check(err is not None and err.code == INVALID_ARGUMENT,
          "key over the limit errors")
    check(err.message == KEY_TOO_LARGE_MSG, "key error message")
    err = check_putentity_sizes(0, 0x100000000)
    check(err is not None and err.code == INVALID_ARGUMENT,
          "entity over the limit errors")
    check(err.message == ENTITY_TOO_LARGE_MSG, "entity error message")
    check(check_putentity_sizes(0, 0) is None, "zero sizes pass")


def main():
    test_batch_init()
    test_varint32()
    test_records()
    test_timestamp_suffix()
    test_status_layout()
    test_ops_table_matches_vtable()
    test_pipeline_success()
    test_pipeline_errors()
    test_putentity_size_boundaries()
    print("all %d checks passed" % CHECKS[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
