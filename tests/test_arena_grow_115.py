"""Tests for node #115 arena grow (tools/arena_grow_115).

pytest-style with a plain-python __main__ runner (pytest is not
installed on this VM).  Every test drives the model end to end:
inputs through the window to observable outputs (returned region
address, deque/map/iterator state, accumulated counter, hook
call sequence), not only pinned constants.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from arena_grow_115 import (
    DEQUE_MAX_SIZE,
    LENGTH_ERROR_MESSAGE,
    MAP_FAILED,
    MMAP_FLAGS,
    MMAP_PROT,
    NODE_BYTES,
    ArenaGrow,
    BadAlloc,
    BadArrayNewLength,
    Hooks,
    LengthError,
    NotifyTracker,
)

MAP_ADDR = 0x80000
REGION = 0x40000000


def make_hooks(fail_mmap=False, fail_new_on=None, wake_raises=False):
    calls = []
    state = {"new_count": 0, "next": 0x50000000}

    def mmap(size, prot, flags):
        calls.append(("mmap", size, prot, flags))
        return MAP_FAILED if fail_mmap else REGION

    def munmap(addr, length):
        calls.append(("munmap", addr, length))

    def operator_new(nbytes):
        state["new_count"] += 1
        calls.append(("new", nbytes))
        if fail_new_on is not None and state["new_count"] == fail_new_on:
            raise BadAlloc("bad_alloc")
        addr = state["next"]
        state["next"] += 0x1000
        return addr

    def operator_delete(addr, nbytes):
        calls.append(("delete", addr, nbytes))

    def wake(head):
        calls.append(("wake", head))
        if wake_raises:
            raise RuntimeError("wake failed")

    hooks = Hooks(mmap=mmap, munmap=munmap, operator_new=operator_new,
                  operator_delete=operator_delete, wake=wake)
    return hooks, calls


def make_arena(hooks, node_counts, map_size=None, start_index=0,
               used=0, notify=None, start_skip=0):
    """Build a deque whose nodes hold the given element counts.

    node_counts[i] = number of descriptors already in node i.
    The start node is start_index; start_skip descriptors of the
    start node are already consumed (start_cur advanced).
    """
    n_nodes = len(node_counts)
    if map_size is None:
        map_size = n_nodes
    chunks = [0x100000 + 0x10000 * i for i in range(max(map_size, n_nodes))]
    slots = [0] * map_size
    for i in range(n_nodes):
        slots[start_index + i] = chunks[i]
    finish_index = start_index + n_nodes - 1
    finish_chunk = chunks[n_nodes - 1]
    start_chunk = chunks[0]
    arena = ArenaGrow(
        hooks, map_address=MAP_ADDR, map_slots=slots,
        start_node_index=start_index,
        start_cur=start_chunk + start_skip * 16,
        start_first=start_chunk, start_last=start_chunk + NODE_BYTES,
        finish_node_index=finish_index,
        finish_cur=finish_chunk + node_counts[-1] * 16,
        finish_first=finish_chunk,
        finish_last=finish_chunk + NODE_BYTES,
        used=used, notify=notify)
    for i in range(n_nodes):
        base = start_skip if i == 0 else 0
        for k in range(base, node_counts[i]):
            arena.chunks.setdefault(chunks[i], {})[k * 16] = (
                0xABC000 + i * 0x100 + k, 0x1000)
    return arena


def test_fast_append_returns_region_and_advances():
    hooks, calls = make_hooks()
    arena = make_arena(hooks, [3], used=100)
    assert arena.grow(0x2000) == REGION
    assert arena.finish_cur == arena.finish_first + 4 * 16
    assert arena.used == 100 + 0x2000
    assert arena.elements()[-1] == (REGION, 0x2000)
    assert ("mmap", 0x2000, MMAP_PROT, MMAP_FLAGS) in calls
    assert not [c for c in calls if c[0] in ("new", "munmap")]


def test_mmap_failure_returns_zero_untouched():
    hooks, calls = make_hooks(fail_mmap=True)
    arena = make_arena(hooks, [3], used=7)
    before = arena.elements()
    assert arena.grow(0x2000) == 0
    assert arena.used == 7
    assert arena.elements() == before
    assert not [c for c in calls if c[0] == "munmap"]


def test_size_zero_returns_zero_without_mmap():
    hooks, calls = make_hooks()
    arena = make_arena(hooks, [3])
    assert arena.grow(0) == 0
    assert calls == []


def test_aux_with_map_slack_installs_fresh_chunk():
    hooks, calls = make_hooks()
    # finish node full but one slot; 4 map slots, finish at index 0
    arena = make_arena(hooks, [31], map_size=4)
    assert arena.grow(0x800) == REGION
    assert ("new", NODE_BYTES) in calls
    assert arena.finish_cur == arena.finish_first  # fresh chunk base
    assert arena.finish_first != 0x100000
    elems = arena.elements()
    assert len(elems) == 32
    assert elems[-1] == (REGION, 0x800)


def test_aux_recenter_moves_nodes_without_map_alloc():
    hooks, calls = make_hooks()
    # 3 nodes (span 2) ending at the map's last slot, map 16:
    # needed 4, 2*4 < 16 -> recenter, no map allocation
    arena = make_arena(hooks, [32, 32, 31], map_size=16, start_index=13)
    old_slots = list(arena.map_slots)
    assert arena.grow(0x800) == REGION
    # no map-sized allocation, only the chunk allocation
    assert [c for c in calls if c[0] == "new"] == [("new", NODE_BYTES)]
    assert not [c for c in calls if c[0] == "delete"]
    # nodes shifted to (16 - 4)//2 = 6
    assert arena.start_node == MAP_ADDR + 6 * 8
    assert arena.map_slots[6] == old_slots[13]
    assert arena.map_slots[8] == old_slots[15]
    assert len(arena.elements()) == 32 + 32 + 32


def test_aux_new_map_doubles_and_frees_old():
    hooks, calls = make_hooks()
    # 1 node, map size 1: needed 2, 2*2 !< 1 -> allocate new map
    arena = make_arena(hooks, [31], map_size=1)
    assert arena.grow(0x800) == REGION
    assert ("new", 32) in calls          # (1 + 1) * 16 bytes
    assert ("delete", MAP_ADDR, 8) in calls
    assert arena.map_size == 4           # 2 * (1 + 1)
    assert arena.start_node == arena.map_address + 8 * 1
    assert len(arena.elements()) == 32


def test_aux_zero_map_size_allocates_three_slots():
    hooks, calls = make_hooks()
    chunk = 0x100000
    # map size field is 0, but the start/finish node slot still
    # physically holds the chunk pointer for the span copy
    arena = ArenaGrow(
        hooks, map_address=MAP_ADDR, map_slots=[chunk],
        map_size_field=0,
        start_node_addr=MAP_ADDR, start_cur=chunk,
        start_first=chunk, start_last=chunk + NODE_BYTES,
        finish_node_addr=MAP_ADDR, finish_cur=chunk + 31 * 16,
        finish_first=chunk, finish_last=chunk + NODE_BYTES)
    arena.chunks[chunk] = {k * 16: (0xABC000 + k, 0x1000)
                           for k in range(31)}
    assert arena.grow(0x800) == REGION
    assert ("new", 0x18) in calls
    assert arena.map_size == 3


def test_length_error_at_deque_max_size():
    hooks, calls = make_hooks()
    chunk = 0x100000
    span = (1 << 54) * 8  # node_span 2^54, (2^54 - 1) * 32 + 31 == max
    arena = ArenaGrow(
        hooks, map_address=MAP_ADDR, map_slots=[chunk],
        start_node_addr=MAP_ADDR, start_cur=chunk + NODE_BYTES,
        start_first=chunk, start_last=chunk + NODE_BYTES,
        finish_node_addr=MAP_ADDR + span,
        finish_cur=chunk + 31 * 16, finish_first=chunk,
        finish_last=chunk + NODE_BYTES)
    try:
        arena.grow(0x800)
    except LengthError as exc:
        assert str(exc) == LENGTH_ERROR_MESSAGE
    else:
        raise AssertionError("expected LengthError")
    # the cleanup pad unmaps the produced region
    assert ("munmap", REGION, 0x800) in calls


def _overflow_arena(hooks, map_size_field):
    chunk = 0x100000
    span_nodes = map_size_field - 1
    return ArenaGrow(
        hooks, map_address=MAP_ADDR, map_slots=[chunk],
        map_size_field=map_size_field,
        start_node_addr=MAP_ADDR, start_cur=chunk,
        start_first=chunk, start_last=chunk + NODE_BYTES,
        finish_node_addr=MAP_ADDR + span_nodes * 8,
        finish_cur=chunk + 31 * 16, finish_first=chunk,
        finish_last=chunk + NODE_BYTES)


def test_map_growth_size_check_bad_alloc():
    hooks, calls = make_hooks()
    arena = _overflow_arena(hooks, (1 << 59) - 1)  # new size 2^60
    try:
        arena.grow(0x800)
    except BadAlloc:
        pass
    else:
        raise AssertionError("expected BadAlloc")
    assert ("munmap", REGION, 0x800) in calls
    assert not [c for c in calls if c[0] == "new"]


def test_map_growth_size_check_bad_array_new_length():
    hooks, calls = make_hooks()
    arena = _overflow_arena(hooks, (1 << 60) - 1)  # new size 2^61
    try:
        arena.grow(0x800)
    except BadArrayNewLength:
        pass
    else:
        raise AssertionError("expected BadArrayNewLength")
    assert ("munmap", REGION, 0x800) in calls


def test_chunk_alloc_failure_unmaps_region_state_unchanged():
    hooks, calls = make_hooks(fail_new_on=1)
    arena = make_arena(hooks, [31], map_size=4, used=55)
    before = arena.elements()
    try:
        arena.grow(0x800)
    except BadAlloc:
        pass
    else:
        raise AssertionError("expected BadAlloc")
    assert ("munmap", REGION, 0x800) in calls
    assert arena.elements() == before
    assert arena.used == 55


def test_map_alloc_failure_unmaps_region_state_unchanged():
    hooks, calls = make_hooks(fail_new_on=1)
    arena = make_arena(hooks, [31], map_size=1, used=55)
    try:
        arena.grow(0x800)
    except BadAlloc:
        pass
    else:
        raise AssertionError("expected BadAlloc")
    assert ("munmap", REGION, 0x800) in calls
    assert arena.map_size == 1
    assert arena.used == 55


def test_notify_absent_and_dormant_do_nothing():
    hooks, calls = make_hooks()
    arena = make_arena(hooks, [3])
    arena.grow(0x800)
    assert not [c for c in calls if c[0] == "wake"]
    tracker = NotifyTracker(head=0x90000, counter=10,
                            head_first=0, head_late=0)
    arena2 = make_arena(hooks, [3], notify=tracker)
    arena2.grow(0x800)
    assert tracker.counter == 10
    assert not [c for c in calls if c[0] == "wake"]


def test_notify_active_adds_counter_and_wakes():
    hooks, calls = make_hooks()
    tracker = NotifyTracker(head=0x90000, counter=10,
                            head_first=1, head_late=0)
    arena = make_arena(hooks, [3], notify=tracker)
    arena.grow(0x800)
    assert tracker.counter == 10 + 0x800
    assert ("wake", 0x90000) in calls
    tracker2 = NotifyTracker(head=0x91000, counter=0,
                             head_first=0, head_late=7)
    arena2 = make_arena(hooks, [3], notify=tracker2)
    arena2.grow(0x40)
    assert tracker2.counter == 0x40
    assert ("wake", 0x91000) in calls


def test_wake_raise_propagates_after_state_lands():
    hooks, calls = make_hooks(wake_raises=True)
    tracker = NotifyTracker(head=0x90000, counter=0, head_first=1)
    arena = make_arena(hooks, [3], used=0, notify=tracker)
    try:
        arena.grow(0x800)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected RuntimeError")
    assert arena.used == 0x800
    assert tracker.counter == 0x800
    assert arena.elements()[-1] == (REGION, 0x800)
    assert not [c for c in calls if c[0] == "munmap"]


def test_two_grows_cross_the_node_boundary():
    hooks, calls = make_hooks()
    arena = make_arena(hooks, [30], map_size=4)
    assert arena.grow(0x100) == REGION      # fast: 31 elements
    assert arena.grow(0x200) == REGION      # aux: chunk install
    elems = arena.elements()
    assert len(elems) == 32
    assert elems[-2] == (REGION, 0x100)
    assert elems[-1] == (REGION, 0x200)
    assert arena.used == 0x300


def test_start_skip_elements_order_preserved():
    hooks, calls = make_hooks()
    arena = make_arena(hooks, [32, 5], map_size=6, start_index=1,
                       start_skip=20)
    elems = arena.elements()
    assert len(elems) == 12 + 5
    assert arena.grow(0x800) == REGION
    assert len(arena.elements()) == 18


def test_packet_records():
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-arena-grow-605d000-115", "records.json")
    records = json.load(open(packet))
    windows = {w["name"]: w for w in records["windows"]}
    assert windows["main"]["start"] == "0x605d000"
    assert windows["main"]["end"] == "0x605d3a1"
    assert windows["main"]["size"] == 929
    assert records["artifact"]["sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["semantics"]["deque_max_size"] == hex(DEQUE_MAX_SIZE)
    assert "0x605d73b" in records["census"]["main"]["direct_calls"]
    assert "0x605d8af" in records["census"]["main"]["direct_calls"]


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
