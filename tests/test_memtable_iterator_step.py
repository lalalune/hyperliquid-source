"""Tests for the RE-001 node #94 memtable iterator step (0x5168160).

Run under pytest when available, or under plain python3 via the
``__main__`` runner below (pytest is not installed on this VM).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from memtable_iterator_step import (  # noqa: E402
    IterState, Inner, known_predicate, parse_length_prefixed, step,
)


def ok_reader(buf, width, flag):
    assert flag == 0
    return (0, 0, None)


def bad_reader(buf, width, flag):
    return (5, 0, "Corrupted memtable entry, per key-value checksum "
                  "verification failed.")


def test_parse_single_byte():
    assert parse_length_prefixed(b"\x05hello") == (1, 5)


def test_parse_two_byte_varint():
    # LEB128: 0x80|0x2c then 0x02 -> 0x2c + 0x02*0x80 = 300.
    assert parse_length_prefixed(bytes([0xAC, 0x02]) + b"x" * 300) == (2, 300)


def test_parse_varint_limit():
    try:
        parse_length_prefixed(bytes([0x80] * 5))
    except ValueError:
        pass
    else:
        raise AssertionError("5 continuation bytes must exceed the limit")


def test_width0_known_ready_slices():
    state = IterState(width=0, ready=True, code=0)
    inner = Inner(buffer=b"\x03abc")
    ok, key, log = step(state, inner)
    assert ok and key == (1, 3, 0x100)
    assert state.buffer_calls == 1


def test_width0_known_stale_code_returns_false():
    state = IterState(width=0, ready=True, code=5, detail="old")
    inner = Inner(buffer=b"\x03abc")
    ok, key, log = step(state, inner)
    assert not ok and key is None
    assert state.buffer_calls == 0


def test_width0_known_not_ready_returns_false():
    # The inline refresh overwrites ready from inner.valid(), so a
    # not-ready case needs an inner iterator that reports invalid.
    state = IterState(width=0, ready=False, code=0)
    inner = Inner(buffer=b"\x03abc", valid=False)
    ok, key, log = step(state, inner)
    assert not ok and key is None


def test_width0_unknown_predicate_false_single_call():
    state = IterState(width=0, ready=True, code=0)
    inner = Inner(buffer=b"\x03abc")
    ok, key, log = step(state, inner, predicate_kind="other",
                        predicate=lambda s: False)
    assert not ok and state.predicate_calls == 1


def test_width0_unknown_predicate_true_slices():
    state = IterState(width=0, ready=False, code=0)
    inner = Inner(buffer=b"\x04abcd")
    ok, key, log = step(state, inner, predicate_kind="other",
                        predicate=lambda s: True)
    assert ok and key == (1, 4, 0x100)
    assert state.predicate_calls == 1


def test_width_nonzero_known_reader_ok_then_slice():
    state = IterState(width=8, ready=True, code=0, detail="old-detail")
    inner = Inner(buffer=b"\x02hi")
    ok, key, log = step(state, inner, reader=ok_reader)
    assert ok and key == (1, 2, 0x100)
    assert state.detail is None and state.code == 0
    assert "free_old_detail" in log
    assert state.buffer_calls == 2  # once for the reader, once for the slice


def test_width_nonzero_known_reader_bad_reports_and_fails():
    state = IterState(width=8, ready=True, code=0)
    inner = Inner(buffer=b"\x02hi")
    ok, key, log = step(state, inner, reader=bad_reader)
    assert not ok and key is None
    assert state.code == 5
    assert any(entry.startswith("report level=3") for entry in log)
    assert "db/memtable.cc" in " ".join(log)


def test_width_nonzero_known_stale_code_skips_reader():
    calls = []

    def counting_reader(buf, width, flag):
        calls.append((buf, width, flag))
        return (0, 0, None)

    state = IterState(width=8, ready=True, code=5)
    inner = Inner(buffer=b"\x02hi")
    ok, key, log = step(state, inner, reader=counting_reader)
    assert not ok and calls == []


def test_width_nonzero_unknown_false_called_twice():
    state = IterState(width=8, ready=True, code=0)
    inner = Inner(buffer=b"\x02hi")
    ok, key, log = step(state, inner, predicate_kind="other",
                        predicate=lambda s: False, reader=ok_reader)
    assert not ok and state.predicate_calls == 2


def test_width_nonzero_unknown_false_then_true_slices_without_reader():
    calls = []
    answers = iter([False, True])

    def flip(s):
        return next(answers)

    def counting_reader(buf, width, flag):
        calls.append(1)
        return (0, 0, None)

    state = IterState(width=8, ready=True, code=0)
    inner = Inner(buffer=b"\x03abc")
    ok, key, log = step(state, inner, predicate_kind="other",
                        predicate=flip, reader=counting_reader)
    assert ok and key == (1, 3, 0x100)
    assert calls == [] and state.predicate_calls == 2


def test_width_nonzero_unknown_reader_ok_then_second_gate():
    seen = []

    def pred(s):
        seen.append(s.code)
        return True

    state = IterState(width=8, ready=True, code=0)
    inner = Inner(buffer=b"\x02hi")
    ok, key, log = step(state, inner, predicate_kind="other",
                        predicate=pred, reader=ok_reader)
    assert ok and key == (1, 2, 0x100)
    assert state.predicate_calls == 2


def test_width_nonzero_unknown_bad_reader_constant_true_reports_and_slices():
    # Literal branch quirk (b): a predicate that still returns True
    # after the failed install reaches the slice after the report.
    state = IterState(width=8, ready=True, code=0)
    inner = Inner(buffer=b"\x02hi")
    ok, key, log = step(state, inner, predicate_kind="other",
                        predicate=lambda s: True, reader=bad_reader)
    assert ok and key == (1, 2, 0x100)
    assert any(entry.startswith("report level=3") for entry in log)


def test_width_nonzero_unknown_bad_reader_known_like_predicate_fails():
    state = IterState(width=8, ready=True, code=0)
    inner = Inner(buffer=b"\x02hi")
    ok, key, log = step(state, inner, predicate_kind="other",
                        predicate=known_predicate, reader=bad_reader)
    assert not ok and key is None


def test_head_other_skips_inner_virtuals():
    state = IterState(width=0, ready=False, code=0)
    inner = Inner(buffer=b"\x03abc")
    ok, key, log = step(state, inner, head_kind="other",
                        head_other=lambda: True)
    assert ok and key == (1, 3, 0x100)
    assert inner.next_calls == 0 and inner.valid_calls == 0


def test_inline_head_runs_perf_and_refresh():
    state = IterState(width=0, ready=False, code=0)
    inner = Inner(buffer=b"\x03abc", valid=True)
    ok, key, log = step(state, inner, perf_present=True, tls_level_byte=2)
    assert ok and state.perf_counter == 1
    assert inner.next_calls == 1 and inner.valid_calls == 1
    assert "perf_getter" in log and "perf_helper" in log


def test_perf_level_byte_not_above_one_skips_helper():
    state = IterState(width=0, ready=False, code=0)
    inner = Inner(buffer=b"\x03abc", valid=True)
    ok, key, log = step(state, inner, perf_present=True, tls_level_byte=1)
    assert ok and state.perf_counter == 0
    assert "perf_helper" not in log


def test_other_key_provider_returns_its_slice():
    state = IterState(width=0, ready=True, code=0)
    inner = Inner(buffer=b"\x03abc", key_other=lambda: (40, 9))
    ok, key, log = step(state, inner)
    assert ok and key == (40, 9, 0x100)
    assert state.buffer_calls == 0


def test_packet_records_parse():
    here = os.path.join(os.path.dirname(__file__), "..", "research",
                         "work-items", "RE-001-memtable-iterator-step-94")
    records = json.load(open(os.path.join(here, "records.json")))
    assert records["window"]["start"] == "0x5168160"
    assert records["window"]["end"] == "0x51683fb"
    assert records["caller_census"]["direct_call_sites"] == []
    assert records["caller_census"]["relative_slots"] == ["0x575b270"]
    assert "0x516833f" in records["reader_call"]["site"]
    assert open(os.path.join(here, "window.txt")).read().count("endbr64") >= 1


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    failed = 0
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - runner reports all
            failed += 1
            print("FAIL %s: %r" % (fn.__name__, exc))
        else:
            print("ok %s" % fn.__name__)
    print("%d passed, %d failed" % (len(TESTS) - failed, failed))
    sys.exit(1 if failed else 0)
