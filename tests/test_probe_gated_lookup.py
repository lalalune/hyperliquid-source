"""Tests for tools/probe_gated_lookup.py (RE-001, node #94 0x516ca20).

pytest-style, with a plain-python3 __main__ runner because pytest
is not installed on this VM.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from probe_gated_lookup import (  # noqa: E402
    MASK_CONST, SEED, install_status, key_slice_length, move_record,
    pair_index, probe_check, probe_length, scan, transform_lookup,
)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def base_kwargs(**over):
    kw = dict(
        host_c18=True, member={"id": "m"}, range_start=0x1000,
        range_end=0x1040, holder_adj=0, out_max=[0], out_string=["old"],
        pairs=[("p0", 2), ("p1", 2)], table18_base=0x8000,
        member90_ptr=0x8008, transform_result=0x42,
        probe_table=None, raw_mode=False, r9_first_byte=0,
        predicate_result=True, transform_pair=(0x2000, 8),
        hash_fn=lambda p, n, s: 0x12345678,
        driver=lambda: (1, 0), timer_start=0,
    )
    kw.update(over)
    return kw


def test_early_gate():
    res = scan(**base_kwargs(host_c18=False))
    check(res.return_value == 0, "early gate returns 0")
    check(res.events == ["early_gate"], "early gate does nothing else: %r"
          % (res.events,))


def test_key_slice_and_probe_length():
    check(key_slice_length(0x1000, 0x1040) == 0x38, "key slice strips 8")
    check(probe_length(0x1000, 0x1040, 0x28) == 0x10,
          "probe length subtracts holder +0x28")


def test_pair_index():
    check(pair_index(0x8008, 0x8000) == 1, "index 1 from +8 pointer")
    check(pair_index(0x8010, 0x8000) == 2, "index 2 from +16 pointer")


def test_max_update_and_replace():
    kw = base_kwargs()
    out_max, out_string = kw["out_max"], kw["out_string"]
    res = scan(**kw)
    check(out_max[0] == 0x42, "max updated to transform result")
    check(out_string[0] == ("p1", 2), "string replaced with pair 1")
    check("string_replaced" in res.events, "replace event logged")


def test_max_unchanged_skips_replace():
    kw = base_kwargs(out_max=[0x100], transform_result=0x42)
    res = scan(**kw)
    check(kw["out_max"][0] == 0x100, "larger existing max kept")
    check(kw["out_string"][0] == "old", "no replace when not larger")
    check("max_unchanged" in res.events, "unchanged event logged")


def test_no_replace_when_string_null():
    kw = base_kwargs(out_string=None)
    res = scan(**kw)
    check(kw["out_max"][0] == 0x42, "max still updated")
    check("string_replaced" not in res.events, "no replace without string")


def test_member_null_skips_key_handling():
    kw = base_kwargs(member=None, transform_result=None)
    res = scan(**kw)
    check(kw["out_max"][0] == 0, "no max update without member")
    check("member_released" not in res.events, "no release without member")


def test_probe_hit_and_miss_math():
    # Craft words so round 0 hits: mask bits of hash 0x12345678.
    h = 0x12345678
    prod = (h * MASK_CONST) & ((1 << 64) - 1)
    mask = (1 << (prod & 63)) | (1 << ((prod >> 6) & 63))
    base = (4 * h) >> 32
    words = [0] * 64
    words[base] = mask
    check(probe_check(words, 4, 1, h) is True, "round-0 hit")
    words[base] = mask & ~(1 << (prod & 63))
    check(probe_check(words, 4, 1, h) is False, "missing bit is a miss")


def test_probe_round_zero_always():
    h = 0x12345678
    prod = (h * MASK_CONST) & ((1 << 64) - 1)
    mask = (1 << (prod & 63)) | (1 << ((prod >> 6) & 63))
    base = (4 * h) >> 32
    words = [0] * 64
    words[base] = mask
    check(probe_check(words, 4, 0, h) is True,
          "round 0 tested even with rounds 0")
    words[base] = 0
    check(probe_check(words, 4, 0, h) is False, "round-0 miss with rounds 0")


def test_probe_rotation_across_rounds():
    h = 0x12345678
    prod0 = (h * MASK_CONST) & ((1 << 64) - 1)
    mask0 = (1 << (prod0 & 63)) | (1 << ((prod0 >> 6) & 63))
    prod1 = ((prod0 >> 12) | (prod0 << 52)) & ((1 << 64) - 1)
    mask1 = (1 << (prod1 & 63)) | (1 << ((prod1 >> 6) & 63))
    base = (4 * h) >> 32
    words = [0] * 64
    words[base] = mask0
    words[base ^ 1] = mask1
    check(probe_check(words, 4, 2, h) is True, "two-round rotated hit")
    words[base ^ 1] = 0
    check(probe_check(words, 4, 2, h) is False, "second-round miss")


def test_null_table_calls_driver_without_probe_counter():
    res = scan(**base_kwargs(probe_table=None))
    check("driver_called" in res.events, "null table goes to driver")
    check(res.counters["plus_0x200"] == 0, "probe-skip driver skips +0x200")


def test_predicate_false_calls_driver():
    table = {"count": 4, "words": [0] * 64, "rounds": 1}
    res = scan(**base_kwargs(probe_table=table, predicate_result=False))
    check("driver_called" in res.events, "predicate false goes to driver")
    check(res.counters["plus_0x200"] == 0, "virtual-false driver skips +0x200")


def test_raw_mode_hashes_range_directly():
    seen = []

    def hash_fn(p, n, s):
        seen.append((p, n, s))
        return 0x12345678

    h = 0x12345678
    prod = (h * MASK_CONST) & ((1 << 64) - 1)
    mask = (1 << (prod & 63)) | (1 << ((prod >> 6) & 63))
    base = (4 * h) >> 32
    words = [0] * 64
    words[base] = mask
    table = {"count": 4, "words": words, "rounds": 1}
    res = scan(**base_kwargs(probe_table=table, raw_mode=True,
                             hash_fn=hash_fn))
    check(seen == [(0x1000, 0x38, SEED)],
          "raw variant hashes the range start and probe length: %r" % (seen,))
    check("probe_hit" in res.events, "raw variant hit reaches driver")
    check(res.counters["plus_0x200"] == 1, "hit path increments +0x200")


def test_probe_miss_path():
    table = {"count": 4, "words": [0] * 64, "rounds": 1}
    res = scan(**base_kwargs(probe_table=table, r9_first_byte=6))
    check("probe_miss" in res.events, "miss event logged")
    check(res.out_sentinel == -1, "miss writes -1 sentinel")
    check("driver_called" not in res.events, "miss never calls driver")
    check("status6_installed" in res.events, "miss + flag installs status 6")
    check(res.counters["plus_0x208"] == 1, "miss increments +0x208")
    check(res.return_value == 0, "miss returns 0")


def test_probe_miss_without_flag():
    table = {"count": 4, "words": [0] * 64, "rounds": 1}
    res = scan(**base_kwargs(probe_table=table, r9_first_byte=0))
    check("status6_installed" not in res.events, "no install without flag")
    check(res.return_value == 0, "miss returns 0")


def test_driver_out_flags():
    res = scan(**base_kwargs(driver=lambda: (0, 1), r9_first_byte=0))
    check(res.return_value == 0, "return is the -0x82 out byte")
    check("status6_installed" in res.events, "driver out81 installs status")
    res2 = scan(**base_kwargs(driver=lambda: (1, 1), r9_first_byte=0))
    check(res2.return_value == 1, "nonzero out82 is returned")
    check("status6_installed" not in res2.events,
          "nonzero out82 skips the install")


def test_driver_status_skip_byte2():
    res = scan(**base_kwargs(driver=lambda: (0, 1), r9_first_byte=2))
    check("status_skip_byte2" in res.events, "byte 2 skips the install")
    check("status6_installed" not in res.events, "no install on byte 2")


def test_epilogue_order():
    res = scan(**base_kwargs(timer_start=0x999))
    check(res.events.index("member_released") <
          res.events.index("timer_destroyed"),
          "release precedes timer destruction: %r" % (res.events,))
    check(res.counters["plus_0x120"] == 1, "epilogue increments +0x120")
    res2 = scan(**base_kwargs(timer_start=0))
    check("timer_destroyed" not in res2.events, "zero start skips destroy")


def test_transform_lookup_tree():
    check(transform_lookup(False, False, True, False, False, 0, 9) == 0,
          "gate virtual false returns 0")
    check(transform_lookup(False, True, False, False, False, 0, 9) == 0,
          "null table returns 0")
    check(transform_lookup(True, None, True, True, False, 0, 9) == 0,
          "empty table returns 0")
    check(transform_lookup(True, None, True, False, True, 0, 9) == 0,
          "end sentinel returns 0")
    check(transform_lookup(True, None, True, False, False, 1, 9) == 0,
          "positive comparator returns 0")
    check(transform_lookup(True, None, True, False, False, 0, 9) == 9,
          "otherwise returns *member +0x90")
    check(transform_lookup(True, None, True, False, False, -1, 9) == 9,
          "non-positive comparator returns the value")


def test_move_record():
    dst = [b"\x01\x02\x03\x04\x05\x06", "old"]
    src = [b"\x06\x00\x00\x00\x00\x00", None]
    old = move_record(dst, src)
    check(dst[0] == b"\x06\x00\x00\x00\x00\x00", "header moved")
    check(dst[1] is None, "pointer moved")
    check(src[0] == b"\x00" * 6 and src[1] is None, "source zeroed")
    check(old == "old", "old destination pointer returned for freeing")
    same = [b"\x06\x00\x00\x00\x00\x00", None]
    check(move_record(same, same) is None, "self-move is a no-op")


def test_packet_files():
    here = os.path.join(ROOT, "research", "work-items",
                        "RE-001-probe-gated-lookup-94")
    for name in ("window.txt", "driver.txt", "transform.txt",
                 "move_helper.txt", "timer_destructor.txt", "thunk.txt",
                 "hash.txt", "records.json", "frames.txt",
                 "relocations.txt", "verify.py", "export_excerpts.py",
                 "census.py", "README.md", "MANIFEST.sha256"):
        check(os.path.exists(os.path.join(here, name)),
              "packet file missing: %s" % name)
    records = json.load(open(os.path.join(here, "records.json")))
    check("mnemonic" not in json.dumps(records),
          "records carry semantic records only, no mnemonic list")
    window = open(os.path.join(here, "window.txt")).read()
    check("516ca20" in window and "516c7e0" in window,
          "window excerpt names the window and its driver call")


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for test in tests:
        test()
        print("ok", test.__name__)
    print("ALL %d MODEL TESTS PASSED" % len(tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
