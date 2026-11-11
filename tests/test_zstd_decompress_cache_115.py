"""Tests for tools/zstd_decompress_cache_115.py.

Every expectation is grounded in the evidence packet
research/work-items/RE-001-zstd-decompress-cache-115/: the excerpts,
the census, and the catalogue's vendor attribution
(GetCachedZSTDUncompressData / ZSTD_createDCtx). Run:
    python3 tests/test_zstd_decompress_cache_115.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))

from zstd_decompress_cache_115 import (
    Entry, SeedState, Table, build_table, claim, cpuid_picker,
    cpu_feature_flag, create_dctx, make_holder, mersenne_step,
    pick_index, table_params, teardown,
)


def check(name, cond):
    assert cond, name
    return 1


def main():
    n = 0

    # --- table params: ncpu <= 8 -> shift 3, count 8, alloc 0x208.
    n += check("ncpu 1", table_params(1) == (3, 8, 0x208))
    n += check("ncpu 8", table_params(8) == (3, 8, 0x208))
    # --- larger: smallest e >= 4 with (1 << e) >= ncpu.
    n += check("ncpu 9", table_params(9) == (4, 16, 0x408))
    n += check("ncpu 16", table_params(16) == (4, 16, 0x408))
    n += check("ncpu 17", table_params(17) == (5, 32, 0x808))
    n += check("ncpu 64", table_params(64) == (6, 64, 0x1008))
    n += check("ncpu 65", table_params(65) == (7, 128, 0x2008))
    n += check("ncpu 1024", table_params(1024) == (10, 1024, 0x10008))
    try:
        table_params(2 ** 57 + 1)
        raise AssertionError("overflow not raised")
    except OverflowError:
        n += check("ncpu 2**57+1 overflows", True)

    # --- fresh table: every entry null, marker -1, claim is itself.
    t = build_table(4)
    n += check("count 8", len(t.entries) == 8 and t.shift == 3)
    n += check("entries init", all(
        e.obj is None and e.marker == -1 and e.claim is e
        for e in t.entries))
    n += check("alloc bytes", t.alloc_bytes == 0x208)

    # --- CPUID picker: leaf 0 -> -1; else EBX>>24.
    n += check("picker no leaf", cpuid_picker(0, 0x01000000) == -1)
    n += check("picker cpu 3", cpuid_picker(1, 0x03000000) == 3)
    n += check("picker cpu 255", cpuid_picker(1, 0xFF000000) == 255)

    # --- LCG seed step (same step as open PR #3613).
    n += check("step 1", mersenne_step(1) == 0x41A7)
    n += check("step 0", mersenne_step(0) == 0)
    n += check("step 0x7fffffff stays", mersenne_step(0x7FFFFFFF) == 0x7FFFFFFF)
    n += check("step twice", mersenne_step(mersenne_step(1)) == mersenne_step(0x41A7))

    # --- pick_index: cpu path masks; -1 path advances the seed once.
    seed = SeedState(1)
    n += check("pick cpu path", pick_index(10, seed, 3) == 2)
    n += check("seed untouched on cpu path", seed.seed == 1)
    seed2 = SeedState(1)
    n += check("pick seed path", pick_index(-1, seed2, 3) == (0x41A7 & 7))
    n += check("seed advanced once", seed2.seed == 0x41A7)

    # --- claim: first claimer wins the shared slot, lazily creating.
    created = []
    t = build_table(4)
    obj, idx = claim(t, 3, SeedState(1), lambda: created.append(object()) or created[-1])
    n += check("first claim index", idx == 3)
    n += check("first claim creates once", len(created) == 1 and obj is created[0])
    n += check("slot now claimed", t.entries[3].claim is None)
    n += check("slot holds object", t.entries[3].obj is obj)
    # Second claim of the same slot: private fallback, index -1.
    obj2, idx2 = claim(t, 3, SeedState(1), lambda: created.append(object()) or created[-1])
    n += check("contention index -1", idx2 == -1)
    n += check("contention fresh object", obj2 is created[1] and obj2 is not obj)
    n += check("slot untouched by contention", t.entries[3].obj is obj)
    n += check("created twice total", len(created) == 2)
    # A different slot still claims shared.
    obj3, idx3 = claim(t, 5, SeedState(1), lambda: created.append(object()) or created[-1])
    n += check("other slot shared", idx3 == 5 and obj3 is created[2])
    # Claim with cpu -1 uses the seed path end to end.
    seed3 = SeedState(1)
    obj4, idx4 = claim(t, -1, seed3, lambda: created.append(object()) or created[-1])
    n += check("seed-path claim index", idx4 == (0x41A7 & 7))
    n += check("seed-path creates", obj4 is created[3])

    # --- teardown frees only owned slot objects, last-to-first.
    freed = []
    t2 = build_table(4)
    shared = []
    claim(t2, 0, SeedState(1), lambda: shared.append(object()) or shared[-1])
    claim(t2, 0, SeedState(1), lambda: shared.append(object()) or shared[-1])
    claim(t2, 7, SeedState(1), lambda: shared.append(object()) or shared[-1])
    got = teardown(t2, freed.append)
    n += check("teardown frees shared only", got == [shared[2], shared[0]])
    n += check("teardown frees in reverse", freed == [shared[2], shared[0]])
    n += check("table dead after teardown", not t2.alive and t2.entries == [])
    n += check("teardown twice frees nothing", teardown(t2, freed.append) == [])

    # --- create_dctx: size, pinned fields, CPU feature probe.
    d = create_dctx(0, 0)
    n += check("dctx size", d["size"] == 0x176F8)
    n += check("dctx 0x7638", d["fields"][0x7638] == 0x8000001)
    n += check("dctx 0x75e0", d["fields"][0x75E0] == 1)
    n += check("dctx last qword", d["fields"][0x176E8] == 0)
    n += check("dctx feature leaf<=6", d["fields"][0x75E4] == 0)
    n += check("feature both bits", cpu_feature_flag(7, 0x108) == 1)
    n += check("feature bmi1 only", cpu_feature_flag(7, 0x8) == 0)
    n += check("feature bmi2 only", cpu_feature_flag(7, 0x100) == 0)
    n += check("feature neither", cpu_feature_flag(7, 0) == 0)
    n += check("feature extra bits ok", cpu_feature_flag(7, 0xFFFFFF08 | 0x100) == 1)

    # --- kind-7 holder factory.
    made = []
    h = make_holder(7, 0x2, 0x8000, lambda: made.append(object()) or made[-1])
    n += check("factory builds kind 7", h is not None)
    n += check("factory vtable", h["vtable"] == 0x64D7438 + 0x10)
    n += check("factory fields", h["field_c"] == 0x2 and h["field_10"] == 0x8000)
    n += check("factory dctx", h["dctx"] is made[0])
    n += check("factory zeroes", h["field_20"] == 0 and h["field_28"] == 0)
    n += check("factory size", h["size"] == 0x38)
    n += check("factory rejects 6", make_holder(6, 0, 0, lambda: None) is None)
    n += check("factory rejects 0x40", make_holder(0x40, 0, 0, lambda: None) is None)

    print("all %d tests passed" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
