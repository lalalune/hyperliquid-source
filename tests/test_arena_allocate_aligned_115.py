"""Tests for node #115 arena aligned allocation (tools/arena_allocate_aligned_115).

pytest-style with a plain-python __main__ runner (pytest is not installed
on this VM).  Every test drives the model end to end: inputs through the
windows to observable outputs (returned pointers and cursor/remaining/
end state), not only pinned constants.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from arena_allocate_aligned_115 import (
    ALIGNMENT,
    REPORT_FILE,
    REPORT_FORMAT,
    REPORT_LEVEL,
    Arena115,
    Hooks,
    TempString,
)


def make_arena(**kw):
    calls = []

    def grow(arena, size):
        calls.append(("grow", size))
        return kw.get("grow_result", 0)

    def new_block(arena, hint):
        calls.append(("new_block", hint))
        return kw.get("new_block_result", 0x10000)

    def report(level, logger, fmt, file, detail):
        calls.append(("report", level, logger, fmt, file, detail))
        if kw.get("report_raises"):
            raise RuntimeError("report failed")

    def build_string(errno_value):
        calls.append(("build_string", errno_value))
        if kw.get("build_raises"):
            raise RuntimeError("build failed")
        return TempString(kw.get("err_text", "No space"),
                          kw.get("data_ptr", 0x20000),
                          kw.get("aux", 0x40),
                          kw.get("is_sso", False))

    def dispose(tmp):
        calls.append(("dispose", tmp.data))

    def sized_delete(ptr, size):
        calls.append(("sized_delete", ptr, size))

    hooks = Hooks(grow=grow, new_block=new_block, report=report,
                  errno=lambda: kw.get("errno_value", 12),
                  build_string=build_string, dispose=dispose,
                  sized_delete=sized_delete)
    arena = Arena115(cursor=kw.get("cursor", 0x1000),
                     remaining=kw.get("remaining", 0x1000),
                     end=kw.get("end", 0),
                     gate=kw.get("gate", 0),
                     block_hint=kw.get("block_hint", 0x4000),
                     big_counter=kw.get("big_counter", 0),
                     hooks=hooks)
    return arena, calls


def test_fast_aligned_returns_cursor_and_advances():
    arena, _ = make_arena(cursor=0x1000, remaining=0x100)
    assert arena.allocate_aligned(0x30, 0, None) == 0x1000
    assert arena.cursor == 0x1030
    assert arena.remaining == 0xD0


def test_fast_misaligned_consumes_padding():
    arena, _ = make_arena(cursor=0x1003, remaining=0x100)
    assert arena.allocate_aligned(0x30, 0, None) == 0x1010
    assert arena.cursor == 0x1040
    assert arena.remaining == 0x100 - (0x30 + 0xD)


def test_fast_exact_fit_empties_remaining():
    arena, _ = make_arena(cursor=0x1000, remaining=0x40)
    assert arena.allocate_aligned(0x40, 0, None) == 0x1000
    assert arena.remaining == 0


def test_fast_insufficient_falls_to_slow_consume_install():
    arena, calls = make_arena(cursor=0x1000, remaining=0x10,
                              gate=0, new_block_result=0x20000,
                              block_hint=0x4000)
    assert arena.allocate_aligned(0x40, 0, None) == 0x20000
    assert ("new_block", 0x4000) in calls
    assert arena.cursor == 0x20040
    assert arena.end == 0x24000
    assert arena.remaining == 0x4000 - 0x40


def test_gate_clear_skips_grow_even_with_quantum():
    arena, calls = make_arena(cursor=0x1000, remaining=0x100, gate=0)
    assert arena.allocate_aligned(0x30, 0x1000, "logger") == 0x1000
    assert not [c for c in calls if c[0] == "grow"]


def test_quantum_zero_skips_grow():
    arena, calls = make_arena(cursor=0x1000, remaining=0x100, gate=0x2000)
    assert arena.allocate_aligned(0x30, 0, "logger") == 0x1000
    assert not [c for c in calls if c[0] == "grow"]


def test_size_zero_returns_aligned_ptr_consuming_pad_only():
    arena, calls = make_arena(cursor=0x1005, remaining=0x100, gate=0x2000)
    assert arena.allocate_aligned(0, 0x1000, "logger") == 0x1010
    assert arena.cursor == 0x1010
    assert arena.remaining == 0x100 - 0xB
    assert not [c for c in calls if c[0] == "grow"]


def test_grow_rounds_up_and_returns_block_untouched_state():
    arena, calls = make_arena(cursor=0x1000, remaining=0x100, gate=0x2000,
                              grow_result=0x30000)
    assert arena.allocate_aligned(100, 64, "logger") == 0x30000
    assert ("grow", 128) in calls
    assert arena.cursor == 0x1000
    assert arena.remaining == 0x100


def test_grow_rounding_boundaries():
    for size, quantum, want in ((128, 64, 128), (1, 4096, 4096),
                                (4097, 4096, 8192), (63, 64, 64)):
        arena, calls = make_arena(gate=0x2000, grow_result=0x30000)
        arena.allocate_aligned(size, quantum, None)
        assert ("grow", want) in calls, (size, quantum, calls)


def test_grow_failure_reports_then_retries_bump_and_frees_heap_temp():
    arena, calls = make_arena(cursor=0x1000, remaining=0x100, gate=0x2000,
                              grow_result=0, err_text="No space left",
                              data_ptr=0x20000, aux=0x40, is_sso=False)
    assert arena.allocate_aligned(0x30, 64, "my-logger") == 0x1000
    assert ("report", REPORT_LEVEL, "my-logger", REPORT_FORMAT,
            REPORT_FILE, "No space left") in calls
    assert ("sized_delete", 0x20000, 0x41) in calls
    assert arena.cursor == 0x1030


def test_grow_failure_with_sso_temp_frees_nothing():
    arena, calls = make_arena(cursor=0x1000, remaining=0x100, gate=0x2000,
                              grow_result=0, is_sso=True)
    arena.allocate_aligned(0x30, 64, None)
    assert not [c for c in calls if c[0] == "sized_delete"]


def test_grow_failure_then_insufficient_bump_goes_slow():
    arena, calls = make_arena(cursor=0x1000, remaining=0x10, gate=0x2000,
                              grow_result=0, new_block_result=0x20000,
                              block_hint=0x4000)
    assert arena.allocate_aligned(0x40, 64, None) == 0x20000
    assert arena.cursor == 0x20040
    assert arena.remaining == 0x4000 - 0x40


def test_report_raise_disposes_temp_and_propagates():
    arena, calls = make_arena(gate=0x2000, grow_result=0,
                              report_raises=True)
    try:
        arena.allocate_aligned(0x30, 64, None)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected RuntimeError")
    assert ("dispose", "No space") in calls
    assert arena.cursor == 0x1000
    assert arena.remaining == 0x1000


def test_slow_big_path_counts_and_tail_jumps_without_install():
    arena, calls = make_arena(block_hint=0x1000, big_counter=7,
                              new_block_result=0x50000)
    assert arena.slow_allocate(0x401, 1) == 0x50000
    assert ("new_block", 0x401) in calls
    assert arena.big_counter == 8
    assert arena.cursor == 0x1000
    assert arena.remaining == 0x1000


def test_slow_gate_grow_install_consume_and_no_consume():
    arena, _ = make_arena(gate=0x8000, block_hint=0x4000,
                          grow_result=0x30000)
    assert arena.slow_allocate(0x100, 1) == 0x30000
    assert arena.cursor == 0x30100
    assert arena.end == 0x38000
    assert arena.remaining == 0x8000 - 0x100
    arena2, _ = make_arena(gate=0x8000, block_hint=0x4000,
                           grow_result=0x30000)
    assert arena2.slow_allocate(0x100, 0) == 0x30000
    assert arena2.cursor == 0x30000
    assert arena2.end == 0x30000 + (0x8000 - 0x100)
    assert arena2.remaining == 0x8000 - 0x100


def test_slow_gate_grow_zero_falls_back_to_block_hint():
    arena, calls = make_arena(gate=0x8000, block_hint=0x4000,
                              grow_result=0, new_block_result=0x20000)
    assert arena.slow_allocate(0x100, 1) == 0x20000
    assert ("grow", 0x8000) in calls
    assert ("new_block", 0x4000) in calls
    assert arena.remaining == 0x4000 - 0x100


def test_slow_gate_clear_goes_straight_to_new_block():
    arena, calls = make_arena(gate=0, block_hint=0x4000,
                              new_block_result=0x20000)
    assert arena.slow_allocate(0x100, 1) == 0x20000
    assert not [c for c in calls if c[0] == "grow"]
    assert ("new_block", 0x4000) in calls


def test_slow_hint_equals_size_leaves_zero_remaining():
    # The block-hint guard (size > hint >> 2) rules out hint == size on
    # the new-block path, so this boundary is exercised via the grow
    # path, where the installed hint is the gate value itself.
    arena, _ = make_arena(gate=0x100, block_hint=0x4000,
                          grow_result=0x20000)
    arena.slow_allocate(0x100, 1)
    assert arena.remaining == 0
    assert arena.cursor == 0x20100


def test_packet_records():
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-arena-allocate-aligned-115", "records.json")
    records = json.load(open(packet))
    assert records["windows"]["main"]["start"] == "0x605d7b0"
    assert records["windows"]["main"]["end"] == "0x605d926"
    assert records["windows"]["main"]["size_bytes"] == 374
    assert records["windows"]["slow"]["start"] == "0x605d6c0"
    assert records["windows"]["slow"]["size_bytes"] == 197
    assert records["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["report"]["format"] == REPORT_FORMAT
    assert records["report"]["file"] == REPORT_FILE
    assert "0x5f11f0e" in records["census"]["main"]["direct_calls"]
    assert "0x605d88d" in records["census"]["slow"]["tail_jumps"]


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failed = 0
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed += 1
            print("FAIL", test.__name__, ":", exc)
        else:
            print("PASS", test.__name__)
    print("%d passed, %d failed" % (len(TESTS) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
