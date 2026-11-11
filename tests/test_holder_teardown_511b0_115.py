"""Tests for the node #115 holder teardown model 0x5d511b0 (RE-001).

pytest is not installed on this VM, so these test_* functions are also
invoked directly by the work-item verify.py.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from holder_teardown_511b0_115 import (  # noqa: E402
    NOOP_SLOT, PHASE2_DTOR, PHASE3_DTOR, REC_DTOR, TAIL_DTOR,
    _item, empty_holder, teardown_holder)


def _record(inline_items, heap_items, ptrs_inline, ptrs_heap,
            ptr_count=0):
    return {"inline_items": inline_items, "heap_items": heap_items,
            "inline_count": 8, "ptrs_inline": ptrs_inline,
            "ptrs_heap": ptrs_heap, "ptr_count": ptr_count}


def test_empty_holder_is_silent():
    holder = empty_holder()
    assert teardown_holder(holder) == []
    assert holder["tail_scalar"] is None


def test_notify_skips_noop_slot_and_calls_others():
    item = _item(0x1000, 5, 0x2000, [NOOP_SLOT, 0x5D40000, NOOP_SLOT])
    holder = empty_holder()
    holder["records"] = [_record([item] + [_item(0, 0, 0x3000 + i * 0x30, [])
                                          for i in range(7)], [], [], [])]
    events = teardown_holder(holder)
    assert ("notify", 0x5D40000, 0) in events
    assert not [e for e in events if e[0] == "notify" and e[1] == NOOP_SLOT]


def test_pop_order_is_reverse_and_inline_skip_rule():
    items = []
    for i in range(8):
        # item i: ptr != addr + 0x10 except item 3, which is inline.
        addr = 0x4000 + i * 0x30
        ptr = addr + 0x10 if i == 3 else 0x9000 + i
        items.append(_item(ptr, i, addr, []))
    holder = empty_holder()
    holder["records"] = [_record(items, [], [], [])]
    events = teardown_holder(holder)
    deletes = [e for e in events if e[0] == "delete"]
    # Reverse order, item 3 skipped, sizes are field10 + 1.
    assert deletes == [("delete", 0x9000 + i, i + 1)
                       for i in (7, 6, 5, 4, 2, 1, 0)]
    assert holder["records"][0]["inline_count"] == 0


def test_heap_items_forward_and_same_skip_rule():
    heap = [_item(0xA000, 10, 0xB000, []),
            _item(0xB010, 20, 0xB000, [])]  # second is inline: ptr == addr+0x10
    holder = empty_holder()
    holder["records"] = [_record(
        [_item(0, 0, 0xC000 + i * 0x30, []) for i in range(8)], heap, [], [])]
    events = teardown_holder(holder)
    assert ("delete", 0xA000, 11) in events
    assert ("delete", 0xB010, 21) not in events
    assert holder["records"][0]["heap_items_cleared"] is True


def test_record_pointer_array_calls_dtor_and_deletes():
    holder = empty_holder()
    holder["records"] = [_record(
        [_item(0, 0, 0xD000 + i * 0x30, []) for i in range(8)], [],
        [0x1111, None, 0x2222] + [None] * 5, [0x3333], ptr_count=8)]
    events = teardown_holder(holder)
    calls = [e for e in events if e[0] == "call" and e[1] == REC_DTOR]
    assert [e[2] for e in calls] == [0x1111, 0x2222, 0x3333]
    assert ("delete", 0x2222, 0x290) in events
    assert holder["records"][0]["ptr_count"] == 0


def test_heap_tail_of_pointer_array_uses_heap_segment():
    # inline_count 8 + one heap pointer: the 9th element comes from heap.
    holder = empty_holder()
    holder["records"] = [_record(
        [_item(0, 0, 0xE000 + i * 0x30, []) for i in range(8)], [],
        [None] * 8, [0x4444], ptr_count=8)]
    events = teardown_holder(holder)
    assert ("call", REC_DTOR, 0x4444) in events


def test_phase_lists_and_tail_in_order():
    holder = empty_holder()
    holder["phase2_inline"] = [0x5001, None] + [None] * 6
    holder["phase2_heap"] = [0x5002]
    holder["phase2_count"] = 8
    holder["phase3_inline"] = [None] * 8
    holder["phase3_heap"] = [0x6001]
    holder["phase3_count"] = 8
    holder["tail_scalar"] = 0x7001
    events = teardown_holder(holder)
    assert events == [("call", PHASE2_DTOR, 0x5001),
                      ("delete", 0x5001, 0xD20),
                      ("call", PHASE2_DTOR, 0x5002),
                      ("delete", 0x5002, 0xD20),
                      ("call", PHASE3_DTOR, 0x6001),
                      ("delete", 0x6001, 0x58),
                      ("call", TAIL_DTOR, 0x7001),
                      ("delete", 0x7001, 0x10)]
    assert holder["phase2_count"] == 0 and holder["phase3_count"] == 0
    assert holder["tail_scalar"] is None


def test_null_tail_scalar_is_silent():
    holder = empty_holder()
    holder["tail_scalar"] = None
    assert teardown_holder(holder) == []


def test_full_holder_end_to_end():
    item = _item(0x8000, 3, 0x8100, [0x5D41111])
    holder = empty_holder()
    holder["records"] = [_record(
        [item] + [_item(0, 0, 0x8200 + i * 0x30, []) for i in range(7)],
        [_item(0x8300, 7, 0x8400, [])],
        [0x9100] + [None] * 7, [], ptr_count=8)]
    holder["phase2_inline"] = [0x9200] + [None] * 7
    holder["phase2_count"] = 8
    holder["tail_scalar"] = 0x9300
    events = teardown_holder(holder)
    assert events[0] == ("notify", 0x5D41111, 0)
    assert ("delete", 0x8000, 4) in events  # pop: item 0, field10 3 + 1
    assert ("delete", 0x8300, 8) in events  # heap item, field10 7 + 1
    assert ("call", REC_DTOR, 0x9100) in events
    assert ("call", PHASE2_DTOR, 0x9200) in events
    assert events[-2:] == [("call", TAIL_DTOR, 0x9300),
                           ("delete", 0x9300, 0x10)]
