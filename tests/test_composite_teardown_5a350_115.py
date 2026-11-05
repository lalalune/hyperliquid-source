"""Tests for tools/composite_teardown_5a350_115.py.

Each test drives the model end to end: holder state in, ordered
observable-effect trace out. Pytest is not installed on this VM,
so the packet's verify.py invokes these functions directly.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from composite_teardown_5a350_115 import (
    PLT_DELETE,
    PLT_MEMSET,
    Holder,
    Record,
    destruct,
)


def _empty_chunk():
    return [Record() for _ in range(8)]


def _full_holder():
    # Three chunks; the map holds count 3. The middle chunk is the
    # only one phase 1 tears down; phases 2 and 3 cover the first
    # and last chunks' live records; phase 4 frees all three
    # chunk blocks plus the map.
    chunks = {
        0x9000: _empty_chunk(),
        0x9100: _empty_chunk(),
        0x9200: _empty_chunk(),
    }
    chunks[0x9100][0] = Record(nodes=["m1"], buf_begin=0xA000,
                               buf_count=2)
    records = {
        0xB000: Record(nodes=["a1"], buf_begin=0xC000, buf_count=1),
        0xB040: Record(),
        0xD000: Record(buf_begin=0xE000, buf_count=3),
        0xD040: Record(),
    }
    return Holder(
        chunk_ptr=0x8000, chunk_count=3,
        rec_a_begin=0xB000, rec_a_end=0xB080,
        chunk_begin=0x8000, chunk_end=0x8010,
        rec_c_end=0xD080, rec_c_begin=0xD000,
        chunk_ptrs=[0x9000, 0x9100, 0x9200],
        chunks=chunks, records=records)


def test_full_holder_phase_order():
    trace = destruct(_full_holder())
    kinds = [t[0] for t in trace]
    expected = (
        # Phase 1: the middle chunk's eight records (the first
        # record carries a node and a heap buffer).
        ["free_node", "memset", "zero", "zero", "free_buffer"]
        + ["memset", "zero", "zero", "free_buffer"] * 7
        # Phase 2: the first chunk's two live records.
        + ["free_node", "memset", "zero", "zero", "free_buffer"]
        + ["memset", "zero", "zero", "free_buffer"]
        # Phase 3: the last chunk's two live records.
        + ["memset", "zero", "zero", "free_buffer"] * 2
        # Phase 4: three chunk blocks, then the map (tail delete).
        + ["free_chunk"] * 3 + ["free_chunk_array_tail"])
    assert kinds == expected
    assert trace[0] == ("free_node", PLT_DELETE, 0x18, "m1")
    assert trace[1] == ("memset", PLT_MEMSET, 0xA000, 16)
    assert trace[4] == ("free_buffer", PLT_DELETE, 0xA000, 16)
    assert trace[-4:-1] == [
        ("free_chunk", PLT_DELETE, 0x9000, 0x200),
        ("free_chunk", PLT_DELETE, 0x9100, 0x200),
        ("free_chunk", PLT_DELETE, 0x9200, 0x200),
    ]
    assert trace[-1] == ("free_chunk_array_tail", PLT_DELETE, 0x8000, 24)


def test_single_chunk_uses_combined_range():
    # Start and finish share one chunk: phases 1 and 2 are
    # skipped and phase 3 walks [start_cur, finish_cur).
    holder = Holder(
        chunk_ptr=0x8000, chunk_count=1,
        rec_a_begin=0xB000, rec_a_end=0xB080,
        chunk_begin=0x8000, chunk_end=0x8000,
        rec_c_end=0xB080, rec_c_begin=0xB000,
        chunk_ptrs=[0x9000],
        chunks={0x9000: _empty_chunk()},
        records={
            0xB000: Record(nodes=["x"], buf_begin=0xC000,
                           buf_count=1),
            0xB040: Record(),
        })
    trace = destruct(holder)
    kinds = [t[0] for t in trace]
    assert kinds == (
        ["free_node", "memset", "zero", "zero", "free_buffer"]
        + ["memset", "zero", "zero", "free_buffer"]
        + ["free_chunk", "free_chunk_array_tail"])
    assert ("free_node", PLT_DELETE, 0x18, "x") in trace
    assert trace[-2] == ("free_chunk", PLT_DELETE, 0x9000, 0x200)
    assert trace[-1] == ("free_chunk_array_tail", PLT_DELETE, 0x8000, 8)


def test_null_map_pointer_returns_plainly():
    # A null chunk map still runs phases 1-3, then returns
    # without freeing any chunk block or the map.
    holder = Holder(
        chunk_ptr=None, chunk_count=2,
        rec_a_begin=0xB000, rec_a_end=0xB040,
        chunk_begin=0x8000, chunk_end=0x8008,
        rec_c_end=0xD040, rec_c_begin=0xD000,
        chunk_ptrs=[0x9000, 0x9100],
        chunks={0x9000: _empty_chunk(), 0x9100: _empty_chunk()},
        records={0xB000: Record(), 0xD000: Record()})
    trace = destruct(holder)
    kinds = [t[0] for t in trace]
    assert kinds == (
        ["memset", "zero", "zero", "free_buffer"] * 2 + ["return"])
    assert trace[-1] == ("return",)


def test_empty_deque_frees_only_chunk_and_map():
    # One chunk, no live records: phase 3 runs zero iterations,
    # phase 4 still frees the chunk block and the map.
    holder = Holder(
        chunk_ptr=0x8000, chunk_count=1,
        rec_a_begin=0xB000, rec_a_end=0xB000,
        chunk_begin=0x8000, chunk_end=0x8000,
        rec_c_end=0xB000, rec_c_begin=0xB000,
        chunk_ptrs=[0x9000],
        chunks={0x9000: _empty_chunk()},
        records={})
    trace = destruct(holder)
    assert trace == [
        ("free_chunk", PLT_DELETE, 0x9000, 0x200),
        ("free_chunk_array_tail", PLT_DELETE, 0x8000, 8),
    ]


def test_inline_record_buffer_memset_but_not_freed():
    # The middle chunk's first record sits at 0x9100, so its
    # inline storage is 0x9138: memset and zeroing still run,
    # but the buffer free is skipped.
    holder = _full_holder()
    holder.chunks[0x9100][0] = Record(buf_begin=0x9138, buf_count=2)
    trace = destruct(holder)
    assert ("memset", PLT_MEMSET, 0x9138, 16) in trace
    assert ("free_buffer", PLT_DELETE, 0x9138, 16) not in trace


def test_null_record_buffer_still_freed_with_size_zero():
    holder = _full_holder()
    holder.records[0xB000] = Record(buf_begin=None, buf_count=0)
    trace = destruct(holder)
    assert ("memset", PLT_MEMSET, None, 0) in trace
    assert ("free_buffer", PLT_DELETE, None, 0) in trace


def test_list_nodes_freed_in_order_before_buffer():
    holder = Holder(
        chunk_ptr=0x8000, chunk_count=1,
        rec_a_begin=0xB000, rec_a_end=0xB040,
        chunk_begin=0x8000, chunk_end=0x8000,
        rec_c_end=0xB040, rec_c_begin=0xB000,
        chunk_ptrs=[0x9000],
        chunks={0x9000: _empty_chunk()},
        records={0xB000: Record(nodes=["n1", "n2"],
                                buf_begin=0xC000, buf_count=1)})
    trace = destruct(holder)
    assert trace[:6] == [
        ("free_node", PLT_DELETE, 0x18, "n1"),
        ("free_node", PLT_DELETE, 0x18, "n2"),
        ("memset", PLT_MEMSET, 0xC000, 8),
        ("zero", "+0x20"),
        ("zero", "+0x18"),
        ("free_buffer", PLT_DELETE, 0xC000, 8),
    ]


def test_chunk_free_size_and_tail_count():
    trace = destruct(_full_holder())
    chunk_frees = [t for t in trace if t[0] == "free_chunk"]
    assert all(t[3] == 0x200 for t in chunk_frees)
    assert len(chunk_frees) == 3
    assert trace[-1] == ("free_chunk_array_tail", PLT_DELETE, 0x8000, 24)
