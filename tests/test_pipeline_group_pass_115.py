"""Tests for tools/pipeline_group_pass_115.py (node #115 step 0x5f801f0).

Run with pytest when available, or directly: python3 this file.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from pipeline_group_pass_115 import PipelineGroupPass, ZERO

MARK = b"M" * 16


def fresh(count, f30, inline=None, heap=None, groups=None):
    inline = list(inline) if inline is not None else [MARK] * 8
    heap = list(heap) if heap is not None else []
    groups = list(groups) if groups is not None else list(range(20))
    return PipelineGroupPass(count, f30, inline, heap, groups)


def test_count_zero_truncates_heap_and_sets_cursor_zero():
    obj = fresh(0, 4, heap=[MARK, MARK])
    calls = obj.run()
    assert calls == []
    assert obj.heap == []
    assert obj.f30 == 0
    # Slots below the old cursor are preserved, not zeroed.
    assert obj.inline[0] == MARK


def test_small_count_fills_from_cursor():
    obj = fresh(3, 1)
    calls = obj.run()
    assert obj.f30 == 3
    assert obj.inline[0] == MARK
    assert obj.inline[1] == ZERO and obj.inline[2] == ZERO
    assert obj.inline[3] == MARK
    assert [c[0] for c in calls] == [0, 1, 2]
    assert calls[0][1] == MARK and calls[1][1] == ZERO
    assert all(c[2] == c[0] for c in calls)


def test_small_count_clamps_cursor_down():
    obj = fresh(3, 5)
    calls = obj.run()
    assert obj.f30 == 3
    assert obj.inline == [MARK] * 8  # no zeroing on the clamp path
    assert len(calls) == 3


def test_small_count_cursor_already_equal():
    obj = fresh(3, 3)
    assert obj.run()
    assert obj.f30 == 3


def test_count_eight_boundary():
    obj = fresh(8, 0, heap=[MARK])
    calls = obj.run()
    assert obj.heap == []  # heap truncated at count <= 8
    assert obj.f30 == 8
    assert len(calls) == 8
    assert all(c[1] == ZERO for c in calls)


def test_count_nine_uses_one_heap_slot():
    heap_slot = b"H" * 16
    obj = fresh(9, 8, inline=[ZERO] * 8, heap=[heap_slot])
    calls = obj.run()
    assert obj.f30 == 8
    assert len(obj.heap) == 1
    assert calls[8] == (8, heap_slot, 8)
    assert len(calls) == 9


def test_large_count_truncates_heap():
    obj = fresh(10, 8, inline=[ZERO] * 8,
                heap=[b"A" * 16, b"B" * 16, b"C" * 16, b"D" * 16, b"E" * 16])
    calls = obj.run()
    assert obj.heap == [b"A" * 16, b"B" * 16]
    assert calls[8][1] == b"A" * 16 and calls[9][1] == b"B" * 16


def test_large_count_grows_heap_with_unpinned_slots():
    obj = fresh(12, 8, inline=[ZERO] * 8, heap=[b"A" * 16])
    calls = obj.run()
    assert obj.heap == [b"A" * 16, None, None, None]
    assert calls[8][1] == b"A" * 16
    assert calls[9][1] is None and calls[11][1] is None


def test_large_count_fills_inline_from_cursor():
    obj = fresh(10, 3)
    obj.run()
    assert obj.f30 == 8
    assert obj.inline[:3] == [MARK] * 3
    assert obj.inline[3:] == [ZERO] * 5


def test_large_count_cursor_past_inline_fills_nothing():
    obj = fresh(10, 9)
    obj.run()
    assert obj.f30 == 8
    assert obj.inline == [MARK] * 8


def test_guards():
    for bad in (fresh(-1, 0), fresh(3, -1), fresh(4, 0, groups=[0, 1])):
        try:
            bad.run()
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError")
    try:
        fresh(2, 0, inline=[MARK] * 7).run()
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for short inline list")


def test_packet_records_match_model_windows():
    import json
    here = os.path.dirname(os.path.abspath(__file__))
    rec = json.load(open(os.path.join(
        here, "..", "research", "work-items",
        "RE-001-pipeline-group-pass-115", "records.json")))
    assert rec["windows"]["step"]["start"] == "0x5f801f0"
    assert rec["windows"]["step"]["stop"] == "0x5f8037d"
    assert rec["census"]["step"]["direct_calls"] == ["0x5f8850b"]
    assert rec["census"]["pergroup"]["direct_calls"] == [
        "0x5da98b8", "0x5f8029a"]
    assert rec["census"]["growhelper"]["direct_calls"] == [
        "0x5da9bad", "0x5f80365"]


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]

if __name__ == "__main__":
    for fn in TESTS:
        fn()
    print("%d model checks pass" % len(TESTS))
