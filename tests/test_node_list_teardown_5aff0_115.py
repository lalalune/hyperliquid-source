"""Model tests for node #115 routine 0x5d5aff0 (node-list teardown)."""
from tools.node_list_teardown_5aff0_115 import destroy


def _holder(nodes, begin, count, inline=False):
    return {"nodes": nodes, "begin": begin, "count": count,
            "inline": inline}


def test_null_head_null_begin_count_zero_still_reaches_buffer_tail():
    holder = _holder([], None, 0)
    assert destroy(holder) == [("zero", 0), ("free_span", 0)]


def test_null_head_heap_buffer_zeroed_then_freed():
    holder = _holder([], 1000, 3)
    assert destroy(holder) == [("zero", 24), ("free_span", 24)]


def test_nodes_freed_in_walk_order_before_buffer_phase():
    holder = _holder([object(), object()], 1000, 2)
    assert destroy(holder) == [("free", 16), ("free", 16),
                               ("zero", 16), ("free_span", 16)]


def test_inline_buffer_zeroed_but_not_freed():
    holder = _holder([object()], 2000, 4, inline=True)
    assert destroy(holder) == [("free", 16), ("zero", 32)]


def test_empty_inline_holder_only_zeroes():
    holder = _holder([], 2000, 1, inline=True)
    assert destroy(holder) == [("zero", 8)]


def test_heap_begin_count_zero_reaches_zero_size_tail_free():
    holder = _holder([], 1000, 0)
    assert destroy(holder) == [("zero", 0), ("free_span", 0)]


def test_null_begin_nonzero_count_is_inconsistent():
    try:
        destroy(_holder([], None, 2))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_node_payload_never_read_only_count_matters():
    holder = _holder([None, None, None], 1000, 0)
    assert destroy(holder) == [("free", 16), ("free", 16),
                               ("free", 16), ("zero", 0),
                               ("free_span", 0)]
