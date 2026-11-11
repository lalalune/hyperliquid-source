"""Tests for tools/zstd_compress_cache_115.py.

Every expectation is grounded in the evidence packet
research/work-items/RE-001-zstd-compress-cache-115/: the excerpts,
the census, the decoded jump tables, and the catalogue's vendor
attribution (StreamingCompress::Create / AddCompressionTypeRecord /
ZSTD_freeCDict). Run:
    python3 tests/test_zstd_compress_cache_115.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))

from zstd_compress_cache_115 import (
    BOUNDS, CDict, TEMPLATE_QWORDS, add_compression_type_record,
    apply_param, bounds_for, cpu_feature_flag, create_cctx, free_cdict,
    make_holder, range_ok, refresh_template, reset_cctx, set_parameter,
)


def check(name, cond):
    assert cond, name
    return 1


def main():
    n = 0

    # --- CPU feature probe: leaf<=6 -> 0; else both BMI bits -> 1.
    n += check("feature leaf 0", cpu_feature_flag(0, 0) == 0)
    n += check("feature leaf 6", cpu_feature_flag(6, 0x108) == 0)
    n += check("feature both bits", cpu_feature_flag(7, 0x108) == 1)
    n += check("feature bmi1 only", cpu_feature_flag(7, 0x8) == 0)
    n += check("feature bmi2 only", cpu_feature_flag(7, 0x100) == 0)
    n += check("feature extra bits ok", cpu_feature_flag(7, 0xFFFFFF08 | 0x100) == 1)

    # --- create_cctx: size, pinned fields, probe.
    c = create_cctx(7, 0x108)
    n += check("cctx size", c["size"] == 0x1480)
    n += check("cctx flag", c["fields"][0x08] == 1)
    n += check("cctx 0x30", c["fields"][0x30] == 1)
    n += check("cctx 0x3c", c["fields"][0x3C] == 3)
    n += check("cctx flag off", create_cctx(0, 0)["fields"][0x08] == 0)

    # --- free_cdict: null -> 0; object -> 0, zeroed, freed.
    n += check("free null cdict", free_cdict(None) == 0)
    d = CDict(backing=object(), custom_free=None)
    n += check("free cdict", free_cdict(d) == 0)
    n += check("cdict freed", d.freed and d.zeroed)

    # --- reset_cctx: plain free path, custom free path, all-null.
    freed = []
    d2 = CDict(backing=object())
    ws = object()
    ctx = {0x370: None, 0x378: None, 0xE48: ws, 0xE68: d2,
           0xE50: 0xDEAD, 0xE88: 0xBEEF}
    got = reset_cctx(ctx, freed.append)
    n += check("reset frees workspace+cdict", got == [ws, d2])
    n += check("reset frees via plain free", freed == [ws])
    n += check("reset zeroes region", all(ctx[o] == 0 for o in range(0xE48, 0xE90, 8)))
    custom_calls = []
    ctx2 = {0x370: lambda opaque, ptr: custom_calls.append((opaque, ptr)),
            0x378: "opaque", 0xE48: "ws", 0xE68: None}
    reset_cctx(ctx2)
    n += check("reset custom free", custom_calls == [("opaque", "ws")])
    ctx3 = {0x370: None, 0xE48: None, 0xE68: None}
    n += check("reset all null frees nothing", reset_cctx(ctx3) == [])

    # --- bounds_for: the full decoded table.
    expect_bounds = {
        10: (0, 1), 100: (-131072, 22), 101: (10, 31),
        102: (6, 30), 103: (6, 30), 104: (1, 30), 105: (3, 7),
        106: (0, 131072), 107: (1, 9), 130: (1340, 131072),
        160: (0, 2), 161: (6, 30), 162: (4, 4096), 163: (1, 8),
        164: (0, 25), 200: (0, 1), 201: (0, 1), 202: (0, 1),
        400: (0, 0), 401: (0, 0), 402: (0, 0), 500: (0, 1),
        1000: (0, 1), 1001: (0, 3), 1002: (0, 2),
        1004: (0, 0x7FFFFFFF), 1005: (0, 1), 1006: (0, 1),
        1007: (0, 1), 1008: (0, 1), 1009: (0, 1), 1010: (0, 1),
        1011: (0, 2), 1012: (0, 1), 1013: (0x400, 0x20000),
        1014: (0, 1), 1015: (0, 2), 1016: (0x400, 0x20000),
    }
    n += check("bounds table size", BOUNDS == expect_bounds)
    for p, (lo, hi) in expect_bounds.items():
        n += check("bounds %d" % p, bounds_for(p) == (0, lo, hi))
    for p in (11, 99, 108, 129, 131, 159, 165, 199, 403, 499,
              501, 999, 1003, 1017, 2000):
        n += check("bounds error %d" % p, bounds_for(p)[0] == -40)

    # --- range_ok edges.
    n += check("range level lo", range_ok(100, -131072) == 1)
    n += check("range level hi", range_ok(100, 22) == 1)
    n += check("range level above", range_ok(100, 23) == 0)
    n += check("range level below", range_ok(100, -131073) == 0)
    n += check("range bool ok", range_ok(10, 1) == 1)
    n += check("range bool no", range_ok(10, 2) == 0)
    n += check("range error param", range_ok(108, 0) == 0)

    # --- apply_param: the compression-level arm (100).
    p = {}
    n += check("level 0 -> 3", apply_param(p, 100, 0) == 3 and p[0x2C] == 3)
    n += check("level 5", apply_param(p, 100, 5) == 5 and p[0x2C] == 5)
    n += check("level clamp hi", apply_param(p, 100, 23) == 22 and p[0x2C] == 22)
    n += check("level negative stores, returns 0",
               apply_param(p, 100, -5) == 0 and p[0x2C] == -5)
    n += check("level min", apply_param(p, 100, -131072) == 0 and p[0x2C] == -131072)
    n += check("level below min clamps",
               apply_param(p, 100, -200000) == 0 and p[0x2C] == -131072)

    # --- apply_param: the cParams block (101..107).
    p = {}
    n += check("windowLog", apply_param(p, 101, 10) == 10 and p[0x04] == 10)
    n += check("windowLog low", apply_param(p, 101, 9) == -42)
    n += check("hashLog", apply_param(p, 102, 6) == 6 and p[0x0C] == 6)
    n += check("chainLog", apply_param(p, 103, 30) == 30 and p[0x08] == 30)
    n += check("searchLog", apply_param(p, 104, 1) == 1 and p[0x10] == 1)
    n += check("minMatch", apply_param(p, 105, 7) == 7 and p[0x14] == 7)
    n += check("targetLength", apply_param(p, 106, 0) == 0 and p[0x18] == 0)
    n += check("strategy", apply_param(p, 107, 9) == 9 and p[0x1C] == 9)
    n += check("strategy high", apply_param(p, 107, 10) == -42)

    # --- apply_param: unlisted params -> -40.
    for bad in (108, 129, 131, 159, 165, 199, 999, 1003):
        n += check("apply rejects %d" % bad, apply_param({}, bad, 1) == -40)

    # --- apply_param: the size arm (130).
    p = {}
    n += check("maxBlock 0", apply_param(p, 130, 0) == 0 and p[0x38] == 0)
    n += check("maxBlock min clamp", apply_param(p, 130, 100) == 1340 and p[0x38] == 1340)
    n += check("maxBlock hi", apply_param(p, 130, 131072) == 131072)
    n += check("maxBlock above", apply_param(p, 130, 131073) == -42)

    # --- apply_param: the 160..164 block.
    p = {}
    n += check("160", apply_param(p, 160, 2) == 2 and p[0x60] == 2)
    n += check("160 high", apply_param(p, 160, 3) == -42)
    n += check("161", apply_param(p, 161, 6) == 6 and p[0x64] == 6)
    n += check("162", apply_param(p, 162, 4096) == 4096 and p[0x6C] == 4096)
    n += check("163", apply_param(p, 163, 8) == 8 and p[0x68] == 8)
    n += check("164", apply_param(p, 164, 25) == 25 and p[0x70] == 25)

    # --- apply_param: the boolean arms (200..202).
    p = {}
    n += check("200 on", apply_param(p, 200, 5) == 1 and p[0x20] == 1)
    n += check("200 off", apply_param(p, 200, 0) == 0 and p[0x20] == 0)
    n += check("201 on", apply_param(p, 201, 1) == 1 and p[0x24] == 1)
    n += check("202 zero -> 1", apply_param(p, 202, 0) == 1 and p[0x28] == 1)
    n += check("202 nonzero -> 0", apply_param(p, 202, 3) == 0 and p[0x28] == 0)

    # --- apply_param: param 10 and the 400/500 arms.
    p = {}
    n += check("param 10", apply_param(p, 10, 1) == 1 and p[0x00] == 1)
    n += check("param 10 out", apply_param(p, 10, 2) == -42)
    n += check("400 zero", apply_param({}, 400, 0) == 0)
    n += check("400 nonzero", apply_param({}, 400, 7) == -40)
    n += check("500 zero", apply_param({}, 500, 0) == 0)
    n += check("500 nonzero", apply_param({}, 500, 1) == -40)

    # --- apply_param: the 1000..1016 block.
    p = {}
    n += check("1000 bool", apply_param(p, 1000, 9) == 1 and p[0x30] == 1)
    n += check("1001", apply_param(p, 1001, 3) == 3 and p[0x44] == 3)
    n += check("1001 high", apply_param(p, 1001, 4) == -42)
    n += check("1002", apply_param(p, 1002, 2) == 2 and p[0x48] == 2)
    n += check("1004", apply_param(p, 1004, 0x7FFFFFFF) == 0x7FFFFFFF and p[0x40] == 0x7FFFFFFF)
    n += check("1005 bool", apply_param(p, 1005, 1) == 1 and p[0x78] == 1)
    n += check("1006", apply_param(p, 1006, 1) == 1 and p[0x7C] == 1)
    n += check("1006 high", apply_param(p, 1006, 2) == -42)
    n += check("1011", apply_param(p, 1011, 2) == 2 and p[0x90] == 2)
    n += check("1011 high", apply_param(p, 1011, 3) == -42)
    n += check("1012 bool", apply_param(p, 1012, 1) == 1 and p[0x94] == 1)
    n += check("1012 out", apply_param(p, 1012, 7) == -42)
    n += check("1013", apply_param(p, 1013, 0x400) == 0x400 and p[0xB0] == 0x400)
    n += check("1013 low", apply_param(p, 1013, 0x3FF) == -42)
    n += check("1014", apply_param(p, 1014, 1) == 1 and p[0xB4] == 1)
    n += check("1015 zero", apply_param(p, 1015, 0) == 0 and p[0xC8] == 0)
    n += check("1015", apply_param(p, 1015, 2) == 2 and p[0xC8] == 2)
    n += check("1015 high", apply_param(p, 1015, 3) == -42)
    n += check("1016", apply_param(p, 1016, 0x20000) == 0x20000 and p[0xD0] == 0x20000)

    # --- set_parameter gates.
    ctx = {0xE18: 1, 0x388: 0, "params": {}}
    n += check("flagged level ok", set_parameter(ctx, 100, 5) == 5)
    n += check("flagged sets dirty", ctx[0x04] == 1)
    n += check("flagged rejects 101", set_parameter(ctx, 101, 10) == -60)
    n += check("flagged rejects 201", set_parameter(ctx, 201, 1) == -60)
    ctx2 = {0xE18: 0, 0x388: 0, "params": {}}
    n += check("unflagged 201", set_parameter(ctx2, 201, 1) == 1)
    n += check("unflagged no dirty", ctx2.get(0x04, 0) == 0)
    n += check("unflagged 201 stored", ctx2["params"][0x24] == 1)
    n += check("unflagged rejects 1017", set_parameter(ctx2, 1017, 1) == -40)
    n += check("unflagged 999 -> apply -40", set_parameter(ctx2, 999, 1) == -40)
    n += check("unflagged 400 zero", set_parameter(ctx2, 400, 0) == 0)
    n += check("unflagged 400 nonzero no guard", set_parameter(ctx2, 400, 5) == -40)
    ctx3 = {0xE18: 0, 0x388: 1, "params": {}}
    n += check("unflagged 400 nonzero guard", set_parameter(ctx3, 400, 5) == -40)

    # --- make_holder: kind gate and the built product.
    def mk_create(max_leaf=7, ebx=0x108):
        return lambda: create_cctx(max_leaf, ebx)
    n += check("factory rejects 6", make_holder(6, TEMPLATE_QWORDS, 2, 0x7FF5, mk_create(), set_parameter) is None)
    n += check("factory rejects 0x40", make_holder(0x40, TEMPLATE_QWORDS, 2, 0x7FF5, mk_create(), set_parameter) is None)
    h = make_holder(7, TEMPLATE_QWORDS, 2, 0x7FF5, mk_create(), set_parameter)
    n += check("factory builds", h is not None)
    n += check("factory size", h["size"] == 0x70)
    n += check("factory table", h["table"] == 0x64D7408 + 0x10)
    n += check("factory kind", h["kind_byte"] == 7)
    n += check("factory template", h["template"] == TEMPLATE_QWORDS)
    n += check("factory fields", h["field_40"] == 2 and h["field_48"] == 0x7FF5)
    n += check("factory zeroes", h["field_58"] == 0 and h["field_60"] == 0)
    n += check("factory cctx flag", h["cctx"][0x08] == 1)
    n += check("factory cctx 0x30", h["cctx"][0x30] == 1)
    n += check("factory sets param 201", h["cctx"]["params"][0x24] == 1)

    # --- refresh_template sizes.
    n += check("template flag18 1", refresh_template(1) == (TEMPLATE_QWORDS, 0x7FF5))
    n += check("template flag18 0", refresh_template(0) == (TEMPLATE_QWORDS, 0x7FF9))
    n += check("template head", TEMPLATE_QWORDS[0] == 0x7FFFFFFFFFF2)
    n += check("template level qword", TEMPLATE_QWORDS[2] == 0x100000000)
    n += check("template tail flag", TEMPLATE_QWORDS[5] == 1)

    # --- add_compression_type_record end to end.
    emitted = []
    def emit_ok(t, payload):
        emitted.append((t, payload))
        return 0
    owner = {"kind": 7, "flag44": 1, "flag18": 1, "holder": None, "array": None}
    n += check("refresh ok", add_compression_type_record(owner, emit_ok, mk_create(), set_parameter) == 0)
    n += check("refresh emitted type 9", emitted == [(9, b"\x07\x00\x00\x00")])
    n += check("refresh installed holder", owner["holder"] is not None and owner["holder"]["size"] == 0x70)
    n += check("refresh array size", owner["array"] == {"size": 0x7FF5})
    owner2 = {"kind": 7, "flag44": 0, "flag18": 0, "holder": None, "array": None}
    n += check("refresh flag18 0", add_compression_type_record(owner2, emit_ok, mk_create(), set_parameter) == 0)
    n += check("refresh array 0x7ff9", owner2["array"] == {"size": 0x7FF9})
    owner3 = {"kind": 0, "flag44": 1, "flag18": 1, "holder": None, "array": None}
    before = len(emitted)
    n += check("refresh kind 0", add_compression_type_record(owner3, emit_ok, mk_create(), set_parameter) == 0)
    n += check("refresh kind 0 emits nothing", len(emitted) == before and owner3["holder"] is None)
    owner4 = {"kind": 7, "flag44": 1, "flag18": 1, "holder": None, "array": None}
    n += check("refresh emit failure", add_compression_type_record(owner4, lambda t, p: 5, mk_create(), set_parameter) == 5)
    n += check("refresh failure clears kind", owner4["kind"] == 0 and owner4["holder"] is None)

    print("all %d tests passed" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
