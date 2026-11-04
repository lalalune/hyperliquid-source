"""Tests for the node #115 memtable iterator step-and-fill
0x5f08790 (RE-014 validation).

Runs under plain python3 via the __main__ runner below (pytest is
not installed on this VM); the packet checker runs this file the
same way. Each test pins one rule from the verbatim disassembly in
research/work-items/RE-014-memtable-iterator-step-fill-115/.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from memtable_iterator_step_fill_115 import (  # noqa: E402
    StepFill, decode_varint, parse_length_prefix,
)

PACKET = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-014-memtable-iterator-step-fill-115",
)


def base(**over):
    cfg = {
        "known_step": True,
        "perf_byte": 0,
        "inner_advance": lambda: None,
        "inner_valid": lambda: True,
        "predicate_known": True,
        "width": 0,
        "provider_default": True,
        "default_buffer": lambda: bytes([5]) + b"hello",
    }
    cfg.update(over)
    return StepFill(**cfg)


def test_length_prefix_single_byte():
    assert parse_length_prefix(bytes([5]) + b"hello") == (1, 5)


def test_length_prefix_zero_length():
    assert parse_length_prefix(bytes([0])) == (1, 0)


def test_length_prefix_boundary_0x7f():
    assert parse_length_prefix(bytes([0x7F]) + b"x" * 127) == (1, 0x7F)


def test_length_prefix_varint():
    # 0x80 0x01 decodes to 128; the slice starts past both bytes.
    assert parse_length_prefix(bytes([0x80, 0x01]) + b"y" * 128) == (2, 128)


def test_varint_bound():
    try:
        decode_varint(bytes([0x80] * 5))
        raise AssertionError("over-long varint must fail")
    except ValueError:
        pass


def test_dispatch_equal_runs_inline_advance_and_perf():
    events = []

    def adv():
        events.append("adv")

    m = base(perf_byte=2, inner_advance=adv,
             perf_helper=lambda: events.append("helper"))
    ok, out = m.run()
    assert ok and out == (1, 5, 0x100)
    assert m.counters["perf_148"] == 1
    assert "inner_advance" in m.events


def test_perf_counter_gated_on_tls_byte():
    m = base(perf_byte=1, perf_helper=lambda: None)
    m.run()
    assert m.counters["perf_148"] == 0


def test_dispatch_unequal_calls_slot_and_skips_inline():
    m = base(known_step=False, dispatch_slot=lambda: None,
             initial_valid=True, initial_status=(0, 0, None))
    ok, out = m.run()
    assert ok and out == (1, 5, 0x100)
    assert "dispatch_slot" in m.events
    assert "inner_advance" not in m.events
    assert m.counters["perf_148"] == 0


def test_width_zero_fill_gate_needs_valid():
    m = base(inner_valid=lambda: False)
    assert m.run() == (False, None)


def test_unknown_predicate_false_returns_false():
    calls = []

    def pred():
        calls.append(1)
        return False

    m = base(width=0, predicate_known=False, predicate=pred)
    assert m.run() == (False, None)
    assert len(calls) == 1


def test_width_nonzero_runs_reader_then_fills():
    seen = {}

    def reader():
        seen["ran"] = True
        return (0, 0, None)

    m = base(width=8, reader=reader)
    ok, out = m.run()
    assert seen["ran"] and ok and out == (1, 5, 0x100)


def test_width_nonzero_valid_false_skips_reader():
    seen = {}

    def reader():
        seen["ran"] = True
        return (0, 0, None)

    m = base(width=8, inner_valid=lambda: False, reader=reader)
    assert m.run() == (False, None)
    assert "ran" not in seen


def test_reader_failure_reports_and_returns_false():
    m = base(width=8, reader=lambda: (3, 1, "detail"),
             report=lambda: None)
    assert m.run() == (False, None)
    assert m.reported == ["detail"]
    assert "report" in m.events


def test_reader_frees_old_detail_after_install():
    m = base(width=8, reader=lambda: (0, 0, "new"),
             initial_status=(0, 0, "old"))
    # The width-nonzero path overwrites status via the reader; the
    # free event must follow the reader call in event order.
    m.run()
    assert m.events.index("reader") < m.events.index("free_old_detail")


def test_unknown_predicate_false_rejoin_second_call():
    calls = {"n": 0}

    def pred():
        calls["n"] += 1
        return calls["n"] == 2

    m = base(width=8, predicate_known=False, predicate=pred,
             reader=lambda: (0, 0, None))
    # First call False -> rejoin -> second call True -> provider.
    ok, out = m.run()
    assert ok and out == (1, 5, 0x100)
    assert calls["n"] == 2


def test_non_default_provider_returns_its_pair():
    m = base(provider_default=False,
             provider=lambda: ("ptr", 42))
    ok, out = m.run()
    assert ok and out == ("ptr", 42, 0x100)


def test_packet_records_window():
    records = json.load(open(os.path.join(PACKET, "records.json")))
    assert records["window"]["address_range"] == "0x5f08790..0x5f08a2b"
    assert records["window"]["size_bytes"] == 603
    assert records["census"]["relative_slots"] == ["0x64cc688"]
    assert records["provider_gate"]["compared_against"].startswith(
        "relocated GOT slot 0x64ed7b0")


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for fn in tests:
        fn()
        print("ok", fn.__name__)
    print("%d tests passed" % len(tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
