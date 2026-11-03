"""Tests for tools/group_stamp_115.py (node #115, RE-001).

Run with pytest when available, or directly: python3 this file.
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from group_stamp_115 import apply_group_stamp, has_zero_stamp, max_stamp

MAX64 = (1 << 64) - 1


def test_predicate_true_false_and_empty():
    assert has_zero_stamp([[5], [0, 7]], 2) is True
    assert has_zero_stamp([[5], [3]], 2) is False
    assert has_zero_stamp([[], []], 2) is False
    assert has_zero_stamp([[0]], 0) is False
    assert has_zero_stamp([[0]], -1) is False


def test_max_unsigned_and_empty():
    assert max_stamp([[5, 9], [2]], 2) == 9
    assert max_stamp([[3, MAX64], [2]], 2) == MAX64
    assert max_stamp([[], []], 2) == 0
    assert max_stamp([[7]], 0) == 0


def test_stamp_path_multi_group():
    # Groups reversed: group 2 takes 1, group 1 takes 2, group 0
    # takes 3 then 4 walking its elements in reverse order.
    out = apply_group_stamp(3, [[3, 0], [0, 7], [5, 5]], 999, 0)
    assert out["path"] == "stamp"
    assert out["groups"] == [[4, 3], [2, 2], [1, 1]]
    assert out["slot"] == 5
    assert out["fd4_written"] is True


def test_stamp_path_single_group():
    out = apply_group_stamp(1, [[9, 0, 4]], 999, 0)
    assert out["path"] == "stamp"
    assert out["groups"] == [[3, 2, 1]]
    assert out["slot"] == 4
    assert out["fd4_written"] is True


def test_stamp_path_flag_increments_first():
    # Flag nonzero: entry slot 1 is incremented to 2 before any
    # group takes a value, so the sequence starts at 2.
    out = apply_group_stamp(3, [[3, 0], [0, 7], [5, 5]], 999, 1)
    assert out["groups"] == [[5, 4], [3, 3], [2, 2]]
    assert out["slot"] == 6
    assert out["fd4_written"] is True


def test_stamp_path_empty_middle_group_consumes_nothing():
    out = apply_group_stamp(3, [[8], [], [0]], 999, 0)
    assert out["groups"] == [[2], [], [1]]
    assert out["slot"] == 3


def test_empty_group_is_max_path():
    out = apply_group_stamp(1, [[]], 999, 0)
    # No zero stamp exists in an empty group, so this is the max
    # path, not the stamp path: max 0 -> computed 1, slot stays 1.
    assert out["path"] == "max"
    assert out["slot"] == 1
    assert out["fd4_written"] is False


def test_max_path_plain():
    out = apply_group_stamp(2, [[5, 9], [2]], 999, 0)
    assert out["path"] == "max"
    assert out["slot"] == 10
    assert out["fd4_written"] is False


def test_max_path_clamped_by_current_slot():
    # Flag nonzero leaves slot at 2; max 0 -> computed 1 < 2, so
    # the slot value wins.
    out = apply_group_stamp(2, [[], []], 999, 1)
    assert out["path"] == "max"
    assert out["slot"] == 2


def test_max_path_wrap_to_zero_keeps_slot():
    # max 2**64-1 -> computed wraps to 0, below the slot, so the
    # slot value (entry 1) wins.
    out = apply_group_stamp(1, [[MAX64]], 999, 0)
    assert out["path"] == "max"
    assert out["slot"] == 1


def test_guards():
    try:
        apply_group_stamp(2, [[1]], 1, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for short groups")
    try:
        apply_group_stamp(-1, [], 1, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative count")


def test_packet_records():
    import json

    packet = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-group-stamp-115"
    records = json.loads((packet / "records.json").read_text())
    assert records["windows"]["predicate"]["address"] == "0x5f6c4e0"
    assert records["windows"]["maximum"]["address"] == "0x5f6c540"
    assert records["windows"]["caller"]["address"] == "0x5f6c5a0"
    assert "0x5f6c71c" in records["census"]["maximum"]["direct_calls"]
    assert "0x5f6c5cd" in records["caller_sites"]["predicate_calls"]


TESTS = [v for k, v in sorted(list(globals().items())) if k.startswith("test_")]

if __name__ == "__main__":
    for test in TESTS:
        test()
    print(f"{len(TESTS)} tests passed")
