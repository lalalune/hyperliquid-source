"""Tests for tools/ttl_runtime_methods_115.py.

End-to-end checks of the TTL runtime methods pinned in
research/work-items/RE-001-ttl-runtime-methods-115/: the TTL value
format (payload + 4-byte little-endian timestamp), FullMergeV2 and
PartialMergeMulti strip/delegate/re-timestamp, the expiry helper and
Filter decision paths, FilterV2/FilterV3 decision mapping,
CreateCompactionFilter wrapping, Prepare/Validate option rules, and
IsInstanceOf matching, with boundary and corruption controls.
"""

import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from ttl_runtime_methods_115 import (  # noqa: E402
    CHANGE_VALUE, Clock, ClockFailure, KEEP, K_BLOB_INDEX,
    K_MERGE_OPERAND, K_VALUE, K_WIDE_COLUMN_ENTITY, Logger,
    PutMergeOperator, RecordingCompactionFilter,
    RecordingCompactionFilterFactory, RecordingMergeOperator, REMOVE,
    TtlCompactionFilter, TtlCompactionFilterFactory, TtlMergeOperator,
    append_timestamp, is_expired, read_timestamp, strip_timestamp,
)

CHECKS = 0


def check(cond, label):
    global CHECKS
    CHECKS += 1
    if not cond:
        raise AssertionError("check failed: " + label)


def ts_value(payload, ts):
    return payload + struct.pack("<I", ts)


def main():
    clock = Clock(1_000_000)
    logger = Logger()

    # --- TTL value format ---
    check(strip_timestamp(ts_value(b"abc", 42)) == b"abc", "strip keeps payload")
    check(read_timestamp(ts_value(b"abc", 42)) == 42, "read timestamp")
    check(append_timestamp(b"abc", 42) == ts_value(b"abc", 42),
          "append round-trips")
    check(append_timestamp(b"", 0) == b"\x00\x00\x00\x00",
          "append to empty payload")
    check(read_timestamp(ts_value(b"x", 0xFFFFFFFF)) == 0xFFFFFFFF,
          "timestamp is 32-bit")
    check(append_timestamp(b"v", 0x1_0000_0042) ==
          ts_value(b"v", 0x42), "timestamp truncated to low 32 bits")

    # --- Expiry helper 0x6203400 ---
    check(is_expired(ts_value(b"v", 100), 10, Clock(109)) is False,
          "ts+ttl == now does not expire")
    check(is_expired(ts_value(b"v", 100), 10, Clock(110)) is False,
          "ts+ttl == now (boundary) does not expire")
    check(is_expired(ts_value(b"v", 100), 10, Clock(111)) is True,
          "ts+ttl < now expires")
    check(is_expired(ts_value(b"v", 100), 0, Clock(10 ** 9)) is False,
          "ttl 0 never expires")
    check(is_expired(ts_value(b"v", 100), -5, Clock(10 ** 9)) is False,
          "negative ttl never expires")
    check(is_expired(ts_value(b"v", 0xFFFFFFF0), 0x20, Clock(0x20)) is False,
          "timestamp sum does not wrap: 32-bit load zero-extends, "
          "the add is 64-bit")

    # --- FullMergeV2 0x6206610 ---
    wrapped = RecordingMergeOperator(reply_value=b"merged-payload")
    ttl_mo = TtlMergeOperator(wrapped, Clock(500))
    log = Logger()
    res = ttl_mo.full_merge_v2(b"k", ts_value(b"old", 100),
                               [ts_value(b"op1", 101),
                                ts_value(b"op2", 102)], log)
    check(res.ok is True, "full merge succeeds")
    check(res.new_value == ts_value(b"merged-payload", 500),
          "full merge re-appends current time")
    check(wrapped.calls[0][1] == b"k", "wrapped gets the key")
    check(wrapped.calls[0][2] == b"old", "wrapped gets stripped existing")
    check(wrapped.calls[0][3] == [b"op1", b"op2"],
          "wrapped gets stripped operands")
    check(log.entries == [], "no error logged on success")

    # Existing value too short (db_ttl_impl.cc:36).
    log = Logger()
    res = ttl_mo.full_merge_v2(b"k", b"ab", [ts_value(b"op", 1)], log)
    check(res.ok is False, "short existing value fails")
    check(log.entries == [(3, "[utilities/ttl/db_ttl_impl.cc:36] Error: "
                          "Could not remove timestamp from existing value.",
                          "utilities/ttl/db_ttl_impl.cc")],
          "short existing logs :36")
    check(len(wrapped.calls) == 1, "wrapped not called after short existing")
    # Exactly 3 bytes is still short; 4 bytes is a timestamp-only value.
    log = Logger()
    res = ttl_mo.full_merge_v2(b"k", b"abc", [ts_value(b"op", 1)], log)
    check(res.ok is False, "3-byte existing value fails")
    log = Logger()
    res = ttl_mo.full_merge_v2(b"k", b"\x01\x02\x03\x04",
                               [ts_value(b"op", 1)], log)
    check(res.ok is True and res.new_value == ts_value(b"merged-payload", 500),
          "4-byte existing value is payload-less but valid")
    # Operand too short (db_ttl_impl.cc:45).
    log = Logger()
    res = ttl_mo.full_merge_v2(b"k", ts_value(b"old", 100),
                               [ts_value(b"good", 1), b"xy"], log)
    check(res.ok is False, "short operand fails")
    check(":45]" in log.entries[0][1], "short operand logs :45")
    check(len(wrapped.calls) == 2, "wrapped not called after short operand")
    # Absent existing value (None) is delegated as None.
    log = Logger()
    res = ttl_mo.full_merge_v2(b"k", None, [ts_value(b"op", 1)], log)
    check(res.ok is True, "absent existing value merges")
    check(wrapped.calls[-1][2] is None, "wrapped gets None existing")
    # Wrapped operator returns false -> false, no timestamp appended.
    bad = RecordingMergeOperator(reply=False)
    ttl_bad = TtlMergeOperator(bad, Clock(500))
    log = Logger()
    res = ttl_bad.full_merge_v2(b"k", ts_value(b"old", 100),
                                [ts_value(b"op", 1)], log)
    check(res.ok is False and res.new_value is None,
          "wrapped false propagates")
    check(log.entries == [], "wrapped false logs nothing")
    # Clock failure (db_ttl_impl.cc:86).
    ttl_noclock = TtlMergeOperator(wrapped, Clock(500, fail=True))
    log = Logger()
    res = ttl_noclock.full_merge_v2(b"k", ts_value(b"old", 100),
                                    [ts_value(b"op", 1)], log)
    check(res.ok is False, "clock failure fails the merge")
    check(":86]" in log.entries[0][1], "clock failure logs :86")
    # PutOperator-style wrapped operator: last operand wins.
    put = TtlMergeOperator(PutMergeOperator(), Clock(777))
    log = Logger()
    res = put.full_merge_v2(b"k", ts_value(b"base", 1),
                            [ts_value(b"a", 2), ts_value(b"b", 3)], log)
    check(res.new_value == ts_value(b"b", 777),
          "put wrapped operator keeps the last operand")

    # --- PartialMergeMulti 0x6201c90 ---
    wrapped = RecordingMergeOperator(reply_value=b"multi")
    ttl_mo = TtlMergeOperator(wrapped, Clock(900))
    log = Logger()
    res = ttl_mo.partial_merge_multi(
        b"k", [ts_value(b"o%d" % i, i) for i in range(40)], log)
    check(res.ok is True, "partial multi succeeds")
    check(res.new_value == ts_value(b"multi", 900),
          "partial multi re-appends current time")
    check(wrapped.calls[0][2] == [b"o%d" % i for i in range(40)],
          "partial multi strips all 40 operands (past the 32-chunk)")
    check(log.entries == [], "no error logged on partial success")
    # Operand too short (db_ttl_impl.cc:108).
    log = Logger()
    res = ttl_mo.partial_merge_multi(b"k", [ts_value(b"ok", 1), b"z"], log)
    check(res.ok is False, "short partial operand fails")
    check(":108]" in log.entries[0][1], "short partial operand logs :108")
    # Clock failure (db_ttl_impl.cc:126).
    ttl_noclock = TtlMergeOperator(wrapped, Clock(900, fail=True))
    log = Logger()
    res = ttl_noclock.partial_merge_multi(b"k", [ts_value(b"o", 1)], log)
    check(res.ok is False, "partial clock failure fails")
    check(":126]" in log.entries[0][1], "partial clock failure logs :126")
    # Wrapped false propagates.
    bad = RecordingMergeOperator(reply=False)
    ttl_bad = TtlMergeOperator(bad, Clock(900))
    res = ttl_bad.partial_merge_multi(b"k", [ts_value(b"o", 1)], Logger())
    check(res.ok is False, "partial wrapped false propagates")
    # Empty operand list merges to the wrapped reply.
    log = Logger()
    res = ttl_mo.partial_merge_multi(b"k", [], log)
    check(res.ok is True and res.new_value == ts_value(b"multi", 900),
          "empty partial operand list still re-timestamps")

    # --- Filter 0x6203520 ---
    keep = RecordingCompactionFilter(decision=KEEP)
    ttl_cf = TtlCompactionFilter(keep, 10, Clock(200))
    # Expired -> kRemove without calling the wrapped filter.
    check(ttl_cf.filter(0, b"k", ts_value(b"v", 100)) == (REMOVE, None, False),
          "expired value removed")
    check(keep.calls == [], "wrapped filter not called for expired value")
    # Not expired, wrapped keeps -> kKeep.
    check(ttl_cf.filter(0, b"k", ts_value(b"v", 195)) == (KEEP, None, False),
          "fresh value kept")
    check(keep.calls[0] == ("filter", 0, b"k", b"v"),
          "wrapped filter gets the stripped value")
    # Wrapped removes -> kRemove.
    drop = RecordingCompactionFilter(decision=REMOVE)
    ttl_drop = TtlCompactionFilter(drop, 10, Clock(200))
    check(ttl_drop.filter(0, b"k", ts_value(b"v", 195)) ==
          (REMOVE, None, False), "wrapped remove propagates")
    # Null wrapped filter -> kKeep.
    ttl_null = TtlCompactionFilter(None, 10, Clock(200))
    check(ttl_null.filter(0, b"k", ts_value(b"v", 195)) ==
          (KEEP, None, False), "null wrapped filter keeps")
    check(ttl_null.filter(0, b"k", ts_value(b"v", 100)) ==
          (REMOVE, None, False), "expired still removed with null wrapped")
    # Wrapped changed the value: original timestamp re-appended.
    check(ttl_cf.filter_with_change(0, b"k", ts_value(b"v", 195),
                                    b"changed") ==
          (KEEP, ts_value(b"changed", 195), True),
          "changed value keeps the original timestamp")
    check(ttl_cf.filter_with_change(0, b"k", ts_value(b"v", 100),
                                    b"changed") == (REMOVE, None, False),
          "expired value is removed even when changed")
    check(ttl_drop.filter_with_change(0, b"k", ts_value(b"v", 195),
                                      b"changed") == (REMOVE, None, False),
          "wrapped remove wins over a changed value")
    # ttl 0 disables expiry.
    ttl_zero = TtlCompactionFilter(keep, 0, Clock(10 ** 9))
    check(ttl_zero.filter(0, b"k", ts_value(b"v", 1)) ==
          (KEEP, None, False), "ttl 0 never expires")

    # --- FilterV2 0x5d2e4a0 / FilterV3 0x5d2f8a0 ---
    ttl_cf = TtlCompactionFilter(keep, 10, Clock(200))
    check(ttl_cf.filter_v2(0, b"k", K_VALUE, ts_value(b"v", 195)) ==
          (KEEP, None, False), "filterv2 kValue keep")
    check(ttl_cf.filter_v2(0, b"k", K_VALUE, ts_value(b"v", 195),
                           b"new") == (CHANGE_VALUE, ts_value(b"new", 195), True),
          "filterv2 kValue change re-appends the timestamp")
    check(ttl_cf.filter_v2(0, b"k", K_VALUE, ts_value(b"v", 100)) ==
          (REMOVE, None, False), "filterv2 kValue expired removes")
    check(ttl_cf.filter_v2(0, b"k", K_MERGE_OPERAND, ts_value(b"v", 195)) ==
          (KEEP, None, False), "filterv2 kMergeOperand keeps by default")
    check(ttl_cf.filter_v2(0, b"k", K_BLOB_INDEX, ts_value(b"v", 195)) ==
          (KEEP, None, False), "filterv2 other value type keeps")
    check(ttl_cf.filter_v3(0, b"k", K_WIDE_COLUMN_ENTITY,
                           ts_value(b"v", 100)) == (KEEP, None, False),
          "filterv3 kWideColumnEntity keeps even when expired")
    check(ttl_cf.filter_v3(0, b"k", K_VALUE, ts_value(b"v", 195), b"new") ==
          (CHANGE_VALUE, ts_value(b"new", 195), True),
          "filterv3 kValue falls through to filterv2")
    check(ttl_cf.filter_v3(0, b"k", K_MERGE_OPERAND, ts_value(b"v", 195)) ==
          (KEEP, None, False), "filterv3 kMergeOperand keeps")
    # FilterMergeOperand override: a wrapped filter that removes merge operands.
    removing = RecordingCompactionFilter(decision=KEEP, merge_operand=True)
    ttl_rm = TtlCompactionFilter(removing, 10, Clock(200))
    check(ttl_rm.filter_v2(0, b"k", K_MERGE_OPERAND, ts_value(b"v", 195)) ==
          (REMOVE, None, False), "filterv2 merge-operand override removes")
    # Shared stub defaults.
    check(ttl_cf.ignore_snapshots() is True, "IgnoreSnapshots defaults true")
    check(ttl_cf.filter_merge_operand() is False,
          "FilterMergeOperand defaults false")
    check(ttl_cf.prepare_blob_output() == KEEP,
          "PrepareBlobOutput defaults kKeep")
    check(ttl_cf.is_stacked_blob_db_internal_compaction_filter() is False,
          "IsStackedBlobDbInternalCompactionFilter defaults false")

    # --- IsInstanceOf ---
    mo = TtlMergeOperator(None, None)
    check(mo.is_instance_of("Merge By TTL") is True,
          "mo matches legacy Merge By TTL")
    check(mo.is_instance_of("TtlMergeOperator") is True,
          "mo matches Name()")
    check(mo.is_instance_of("") is False, "mo empty name never matches")
    check(mo.is_instance_of("TtlCompactionFilter") is False,
          "mo rejects other names")
    cf = TtlCompactionFilter(None, 0, None)
    check(cf.is_instance_of("Delete By TTL") is True,
          "cf matches legacy Delete By TTL")
    check(cf.is_instance_of("TtlCompactionFilter") is True,
          "cf matches Name()")
    check(cf.is_instance_of("Merge By TTL") is False,
          "cf rejects the merge legacy name")
    check(cf.is_instance_of("") is False, "cf empty name never matches")
    cff = TtlCompactionFilterFactory(0, None, None)
    check(cff.is_instance_of("TtlCompactionFilterFactory") is True,
          "cff matches Name()")
    check(cff.is_instance_of("") is False, "cff empty name never matches")
    check(cff.is_instance_of("Delete By TTL") is False,
          "cff has no legacy name")
    # Slot 17 wrapped accessors and slot 18 short names.
    wrapped_mo = RecordingMergeOperator()
    mo2 = TtlMergeOperator(wrapped_mo, Clock(1))
    check(mo2.wrapped_operator() is wrapped_mo, "mo slot 17 returns wrapped")
    check(mo2.short_name() == "", "mo slot 18 is empty")
    wrapped_cf = RecordingCompactionFilter()
    cf2 = TtlCompactionFilter(wrapped_cf, 5, Clock(1))
    check(cf2.wrapped_filter() is wrapped_cf, "cf slot 17 returns wrapped")
    check(cf2.short_name() == "", "cf slot 18 is empty")
    wrapped_cff = RecordingCompactionFilterFactory()
    cff2 = TtlCompactionFilterFactory(5, Clock(1), wrapped_cff)
    check(cff2.wrapped_factory() is wrapped_cff,
          "cff slot 17 returns wrapped")
    check(cff2.short_name() == "", "cff slot 18 is empty")

    # --- PrepareOptions / ValidateOptions ---
    class ConfigOptions:
        def __init__(self, clock):
            self._clock = clock

        def resolve_clock(self):
            return self._clock

    cfg = ConfigOptions(Clock(42))
    mo3 = TtlMergeOperator(wrapped_mo, None)
    check(mo3.prepare_options(cfg) is True, "mo prepare resolves clock")
    check(mo3.clock.now_seconds == 42, "mo clock resolved from options")
    check(mo3.validate_options() == (True, None),
          "mo validates with wrapped + clock")
    check(TtlMergeOperator(None, Clock(1)).validate_options()[0] is False,
          "mo validates false without wrapped")
    check(TtlMergeOperator(None, Clock(1)).validate_options()[1] ==
          "UserMergeOperator required by TtlMergeOperator",
          "mo missing wrapped error names the option")
    check(TtlMergeOperator(wrapped_mo, None).validate_options()[1] ==
          "SystemClock required by TtlMergeOperator",
          "mo missing clock error names the option")
    cf3 = TtlCompactionFilter(wrapped_cf, 5, None)
    check(cf3.prepare_options(cfg) is True, "cf prepare resolves clock")
    check(cf3.validate_options() == (True, None), "cf validates with clock")
    check(TtlCompactionFilter(wrapped_cf, 5, None).validate_options()[1] ==
          "SystemClock required by TtlCompactionFilter",
          "cf missing clock error names the option")
    cff3 = TtlCompactionFilterFactory(5, None, wrapped_cff)
    check(cff3.prepare_options(cfg) is True, "cff prepare resolves clock")
    check(cff3.validate_options() == (True, None), "cff validates with clock")
    check(TtlCompactionFilterFactory(5, None, wrapped_cff)
          .validate_options()[1] ==
          "SystemClock required by TtlCompactionFilterFactory",
          "cff missing clock error names the option")

    # --- CreateCompactionFilter 0x6202ba0 ---
    inner = RecordingCompactionFilter(decision=KEEP)
    factory = RecordingCompactionFilterFactory(wrapped_filter=inner)
    ttl_cff = TtlCompactionFilterFactory(30, Clock(1000), factory)
    made = ttl_cff.create_compaction_filter({"filter_factory": factory})
    check(isinstance(made, TtlCompactionFilter),
          "create returns a TtlCompactionFilter")
    check(made.wrapped_filter() is inner, "created filter wraps the factory filter")
    check(made.ttl == 30, "created filter inherits ttl")
    check(made.clock.now_seconds == 1000, "created filter inherits clock")
    check(ttl_cff.create_compaction_filter({"filter_factory": None}) is None,
          "null context filter factory creates nothing")
    check(ttl_cff.create_compaction_filter(None) is None,
          "null context creates nothing")
    check(factory.calls == [{"filter_factory": factory}],
          "wrapped factory called once with the context")
    # The created filter behaves end to end.
    check(made.filter(0, b"k", ts_value(b"v", 990)) == (KEEP, None, False),
          "created filter keeps a fresh value")
    check(made.filter(0, b"k", ts_value(b"v", 900)) == (REMOVE, None, False),
          "created filter removes an expired value")

    # --- Seeded random cross-checks against an independent reference ---
    rng = random.Random(115)
    for trial in range(60):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 20)))
        ts = rng.randrange(0, 2 ** 32)
        ttl = rng.randrange(0, 1000)
        now = rng.randrange(0, 2 ** 32)
        value = ts_value(payload, ts)
        # Reference expiry: (uint32)ts + ttl < now as a 64-bit signed
        # sum (the binary zero-extends the 4-byte load, then adds
        # the sign-extended ttl in 64 bits: no 32-bit wrap), ttl > 0.
        ref = ttl > 0 and (ts + ttl) < now
        check(is_expired(value, ttl, Clock(now)) == ref,
              "random expiry trial %d" % trial)
        # Reference strip/append round-trip.
        check(strip_timestamp(append_timestamp(payload, now)) == payload,
              "random strip/append trial %d" % trial)
        check(read_timestamp(append_timestamp(payload, ts)) == ts,
              "random timestamp trial %d" % trial)
    for trial in range(30):
        n = rng.randrange(0, 70)
        operands = [ts_value(bytes(rng.randrange(256)
                                   for _ in range(rng.randrange(0, 8))),
                             rng.randrange(0, 2 ** 32)) for _ in range(n)]
        wrapped = RecordingMergeOperator(reply_value=b"r")
        ttl_mo = TtlMergeOperator(wrapped, Clock(1234))
        res = ttl_mo.partial_merge_multi(b"k", operands, Logger())
        check(res.ok is True, "random partial trial %d succeeds" % trial)
        check(res.new_value == ts_value(b"r", 1234),
              "random partial trial %d re-timestamps" % trial)
        check(wrapped.calls[0][2] ==
              [strip_timestamp(o) for o in operands],
              "random partial trial %d strips every operand" % trial)
    for trial in range(30):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 12)))
        ts = rng.randrange(0, 2 ** 32)
        ttl = rng.randrange(0, 500)
        now = rng.randrange(0, 2 ** 32)
        decision = rng.choice([KEEP, REMOVE])
        wrapped_cf = RecordingCompactionFilter(decision=decision)
        ttl_cf = TtlCompactionFilter(wrapped_cf, ttl, Clock(now))
        value = ts_value(payload, ts)
        expired = ttl > 0 and (ts + ttl) < now
        got = ttl_cf.filter(0, b"k", value)
        if expired:
            check(got == (REMOVE, None, False),
                  "random filter trial %d expired removes" % trial)
        elif decision == REMOVE:
            check(got == (REMOVE, None, False),
                  "random filter trial %d wrapped remove" % trial)
        else:
            check(got == (KEEP, None, False),
                  "random filter trial %d keep" % trial)

    print("%d checks passed" % CHECKS)


if __name__ == "__main__":
    main()
