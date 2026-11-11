"""Tests for tools/ts_gate_ops_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_ts_gate_ops_115.py

Every expectation is grounded in the packet
research/work-items/RE-001-ts-gate-ops-115/: the record type
bytes and vtable slots come from the census and relocation
records, the error strings from the .rodata bytes they name,
and the pipeline order from the wrapper/impl/middle excerpts.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from ts_gate_ops_115 import (
    OPS, VTABLE_ADDR, TYPEINFO_NAME, MIDDLE_SLOTS, RECORD_TYPES,
    OK_STUB, GATE, RESOLVER, HEX_HELPER, NIBBLE, WRAPPERS, IMPLS,
    MIDDLES, INNERS,
    OK, INVALID_ARGUMENT,
    NO_CF_HANDLE_MSG, NO_TIMESTAMP_PREFIX, NO_TIMESTAMP_SUFFIX,
    TS_MISMATCH_PREFIX, TS_DISABLED_MSG, TS_SIZE_MISMATCH_MSG,
    READ_TS_PREFIX, READ_TS_SUFFIX,
    Status, Slice, nibble, hex_or_copy, Resolved, Factory, CfObj,
    gate, resolve, put_varint32, WriteBatch, middle, DbStub,
    run_operation,
)

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("check failed: %s" % label)


def test_status_layout():
    s = Status()
    check(s.ok() and s.code == 0 and s.subcode == 0
          and s.message is None, "OK status is code 0, no message")
    bad = Status(INVALID_ARGUMENT, 0, "x")
    copy = bad.copy()
    check(copy.code == INVALID_ARGUMENT and copy.message == "x",
          "wrapper copies a failure Status")


def test_nibble_and_hex():
    for n, expected in [(0, "0"), (9, "9"), (10, "A"), (15, "F")]:
        check(nibble(n) == expected, "nibble %d -> %s" % (n, expected))
    check(hex_or_copy(b"\x00\xff\xab", 0) == b"\x00\xff\xab",
          "hex_flag 0 copies verbatim")
    check(hex_or_copy(b"\x00\xff\xab", 1) == b"00FFAB",
          "hex_flag 1 gives UPPERCASE hex")
    check(hex_or_copy(b"", 1) == b"", "empty slice hexes to empty")
    try:
        nibble(16)
        check(False, "nibble rejects out-of-range input")
    except ValueError:
        check(True, "nibble rejects out-of-range input")


def test_gate_branches():
    ts = Slice(b"\x00" * 8)
    check(gate(None, ts, 0).message == NO_CF_HANDLE_MSG,
          "gate: null factory -> 'column family handle cannot be null'")
    f0 = Factory(Resolved(0), name="default")
    msg = gate(f0, ts, 0).message
    check(msg == NO_TIMESTAMP_PREFIX + "default" + NO_TIMESTAMP_SUFFIX,
          "gate: ts 0 -> does-not-enable-timestamp message")
    f8 = Factory(Resolved(8), name="default")
    check(gate(f8, ts, 0).ok(), "gate: matching size, flag 0 -> OK")
    msg = gate(f8, Slice(b"\x00" * 4), 0).message
    check(msg == TS_MISMATCH_PREFIX + "8, 4 given",
          "gate: mismatch names expect 8, given 4")
    check(gate(f8, ts, 1).ok(),
          "gate: flag 1 with empty low string -> OK (len 0 skips)")
    f_stub = Factory(Resolved(8), name="default", low=b"\x01\x02")
    check(gate(f_stub, ts, 1).ok(),
          "gate: flag 1, slot 0xc8 is the always-OK stub -> OK")

    def validator(_resolved, _ts_slice, _low):
        return -1

    f_bad = Factory(Resolved(8), name="default", low=b"\x01\x02",
                    )
    f_bad.resolved.slot_c8 = validator
    msg = gate(f_bad, ts, 1).message
    check(msg == READ_TS_PREFIX + "0000000000000000" +
          READ_TS_SUFFIX + "0102",
          "gate: validator < 0 -> read-timestamp message, hex uppercase")

    def validator_ok(_resolved, _ts_slice, _low):
        return 0

    f_ok = Factory(Resolved(8), name="default", low=b"\x01\x02")
    f_ok.resolved.slot_c8 = validator_ok
    check(gate(f_ok, ts, 1).ok(),
          "gate: validator >= 0 -> OK")


def test_resolver_branches():
    ts = Slice(b"\x00" * 8)
    check(resolve(None, ts).message == NO_CF_HANDLE_MSG,
          "resolver: null cf -> 'column family handle cannot be null'")
    check(resolve(CfObj(0), ts).message == TS_DISABLED_MSG,
          "resolver: ts 0 -> 'timestamp disabled'")
    check(resolve(CfObj(8), Slice(b"\x00" * 4)).message ==
          TS_SIZE_MISMATCH_MSG,
          "resolver: size mismatch -> 'timestamp size mismatch'")
    check(resolve(CfObj(8), ts).ok(),
          "resolver: matching size -> OK")


def test_batch_init():
    b = WriteBatch(ts_size=8)
    check(bytes(b.rep) == b"\x00" * 12, "rep starts as 12 NUL bytes")
    check(b.sequence() == 0 and b.count() == 0,
          "rep header: sequence 0, count 0")
    check(b.ts_size == 8, "batch+0x38 holds the timestamp size")
    check(b.flag_22 == 0, "batch+0x22 starts 0")
    check(put_varint32(0) == b"\x00", "varint32 0")
    check(put_varint32(300) == b"\xac\x02", "varint32 300")


def test_middle_assembly():
    ts = Slice(b"\x11" * 8)
    key = Slice(b"key")
    value = Slice(b"val")
    end = Slice(b"end")
    # Put: key parts [key1, ts], value parts [value].
    b = WriteBatch(ts_size=8)
    status, rec = middle("put", b, CfObj(8, cf_id=0), key, ts, value)
    check(status.ok(), "middle put succeeds")
    check(b.flag_22 == 1, "middle sets batch+0x22 = 1")
    check(b.count() == 1, "one record appended")
    check(rec[0] == 0x01, "put record type default-CF 0x01")
    check(rec[1] == 11 and rec[2:5] == b"key",
          "put record: key length 11 (key 3 + ts 8), then key bytes")
    check(rec[5:13] == b"\x11" * 8,
          "put record carries the timestamp as the second key part")
    check(rec[13] == 3 and rec[14:17] == b"val",
          "put record carries the value")
    check(len(rec) == 17, "put record is 17 bytes total")
    # With a CF id the type byte flips and the id is encoded.
    b2 = WriteBatch(ts_size=8)
    status, rec = middle("put", b2, CfObj(8, cf_id=3), key, ts, value)
    check(rec[0] == 0x05 and rec[1] == 3,
          "put with cf_id 3: type 0x05 then varint id 3")
    # Delete: no value parts.
    b3 = WriteBatch(ts_size=8)
    status, rec = middle("delete", b3, CfObj(8), key, ts)
    check(rec[0] == 0x00 and len(rec) == 13,
          "delete record: type 0x00, key parts only (13 bytes)")
    # SingleDelete.
    b4 = WriteBatch(ts_size=8)
    status, rec = middle("singledelete", b4, CfObj(8), key, ts)
    check(rec[0] == 0x07, "singledelete record type 0x07")
    # DeleteRange: end-key parts [end1, ts].
    b5 = WriteBatch(ts_size=8)
    status, rec = middle("deleterange", b5, CfObj(8), key, ts, end)
    check(rec[0] == 0x0F, "deleterange record type 0x0f")
    check(rec[13] == 11 and rec[14:17] == b"end",
          "deleterange record carries the end key length (end 3 + ts 8) and bytes")
    check(rec[17:25] == b"\x11" * 8,
          "deleterange record appends ts to the end key too")
    check(len(rec) == 25, "deleterange record is 25 bytes total")
    # Merge.
    b6 = WriteBatch(ts_size=8)
    status, rec = middle("merge", b6, CfObj(8), key, ts, value)
    check(rec[0] == 0x02, "merge record type 0x02")
    # Resolver failure propagates and nothing is appended.
    b7 = WriteBatch(ts_size=8)
    status, rec = middle("put", b7, CfObj(0), key, ts, value)
    check(not status.ok() and status.message == TS_DISABLED_MSG,
          "middle propagates the resolver failure")
    check(b7.count() == 0 and b7.flag_22 == 0,
          "failed middle appends nothing and leaves +0x22 clear")


def test_tables_match_packet():
    check(VTABLE_ADDR == 0x64CD498, "WriteBatch vtable base")
    check(TYPEINFO_NAME == "rocksdb::WriteBatch",
          "typeinfo name")
    check(MIDDLE_SLOTS == {"put": 4, "delete": 15,
                            "singledelete": 20, "deleterange": 25,
                            "merge": 10},
          "middle vtable slots: put 4, delete 15, singledelete 20, "
          "deleterange 25, merge 10")
    check(RECORD_TYPES["put"] == (0x01, 0x05)
          and RECORD_TYPES["delete"] == (0x00, 0x04)
          and RECORD_TYPES["singledelete"] == (0x07, 0x08)
          and RECORD_TYPES["deleterange"] == (0x0F, 0x0E)
          and RECORD_TYPES["merge"] == (0x02, 0x06),
          "record type bytes match the packet")
    check(GATE == 0x5E882B0 and RESOLVER == 0x5FB6910
          and HEX_HELPER == 0x61C7E30 and NIBBLE == 0x61C7DA0,
          "gate / resolver / hex / nibble addresses")
    check(OK_STUB == 0x5D48400, "always-OK stub address")
    check(set(WRAPPERS) == set(OPS) and set(IMPLS) == set(OPS)
          and set(MIDDLES) == set(OPS) and set(INNERS) == set(OPS),
          "one wrapper, impl, middle and inner per operation")
    check(WRAPPERS["merge"] == 0x5E960A0
          and MIDDLES["merge"] == 0x5FC4220,
          "merge wrapper/middle are the fifth pair found this cycle")


def test_pipeline_success():
    ts = Slice(b"\x00" * 8)
    factory = Factory(Resolved(8), name="default")
    db = DbStub()
    out, batch, _db = run_operation(
        "put", factory, CfObj(8), ts, Slice(b"k"), Slice(b"v"),
        db=db)
    check(out.ok(), "pipeline put: out OK")
    check(batch is not None and batch.destroyed,
          "pipeline put: batch destroyed on the success path")
    check(batch.count() == 1 and batch.flag_22 == 1,
          "pipeline put: one record, +0x22 set")
    check(len(db.dispatches) == 1 and db.dispatches[0][0] == "put",
          "pipeline put: slot 0xe0 dispatch recorded once")
    check(db.dispatches[0][2] == 8,
          "pipeline put: dispatch sees the resolved ts size")
    # Every operation runs end to end.
    for op in OPS:
        extra = Slice(b"v") if op in ("put", "merge") else (
            Slice(b"e") if op == "deleterange" else None)
        out, batch, db2 = run_operation(
            op, factory, CfObj(8), ts, Slice(b"k"), extra)
        check(out.ok() and batch.count() == 1,
              "pipeline %s succeeds end to end" % op)


def test_pipeline_errors():
    ts = Slice(b"\x00" * 8)
    # Gate failure: no impl, no dispatch, batch never built.
    f0 = Factory(Resolved(0), name="default")
    out, batch, db = run_operation(
        "put", f0, CfObj(0), ts, Slice(b"k"), Slice(b"v"))
    check(not out.ok() and "does not enable timestamp" in out.message,
          "pipeline: gate failure surfaces the gate message")
    check(batch is None and db.dispatches == [],
          "pipeline: gate failure never reaches the impl/dispatch")
    # Resolver failure: batch built and destroyed, no dispatch.
    factory = Factory(Resolved(8), name="default")
    out, batch, db = run_operation(
        "put", factory, CfObj(0), ts, Slice(b"k"), Slice(b"v"))
    check(not out.ok() and out.message == TS_DISABLED_MSG,
          "pipeline: resolver failure surfaces 'timestamp disabled'")
    check(batch is not None and batch.destroyed
          and db.dispatches == [],
          "pipeline: resolver failure destroys the batch, no dispatch")
    # Size mismatch at the gate.
    out, batch, db = run_operation(
        "put", factory, CfObj(8), Slice(b"\x00" * 4), Slice(b"k"),
        Slice(b"v"))
    check(not out.ok() and "Timestamp sizes mismatch" in out.message,
          "pipeline: gate mismatch surfaces the mismatch message")


def main():
    test_status_layout()
    test_nibble_and_hex()
    test_gate_branches()
    test_resolver_branches()
    test_batch_init()
    test_middle_assembly()
    test_tables_match_packet()
    test_pipeline_success()
    test_pipeline_errors()
    print("all %d checks passed" % CHECKS[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
