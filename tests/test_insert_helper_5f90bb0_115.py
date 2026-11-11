"""Tests for the node #115 insert helper 0x5f90bb0 model.

Run with pytest, or directly with plain python3 (no pytest installed
on this VM): ``python3 tests/test_insert_helper_5f90bb0_115.py``
prints ``N tests passed`` on success.
"""

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from insert_helper_5f90bb0_115 import (  # noqa: E402
    BB, SINGLE, insert, need_rehash, new_table,
)

PACKET_DIR = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-insert-helper-5f90bb0-115"


def _list_keys(state):
    keys = []
    node = state["head"]
    while node is not None:
        keys.append(state["nodes"][node]["key"])
        node = state["nodes"][node]["next"]
    return keys


def test_first_insert_grows_and_links_as_head():
    st = new_table(1.0)
    node, inserted = insert(st, 5)
    assert inserted is True
    assert node == 0x10000
    assert st["element_count"] == 1
    assert st["bucket_count"] == 13
    assert st["next_resize"] == 13
    assert st["head"] == node
    assert st["buckets"][5] == BB
    assert all(slot is None for i, slot in enumerate(st["buckets"]) if i != 5)
    assert _list_keys(st) == [5]


def test_duplicate_returns_existing_node_and_changes_nothing():
    st = new_table(1.0)
    node, _ = insert(st, 5)
    before = copy.deepcopy(st)
    again, inserted = insert(st, 5)
    assert inserted is False
    assert again == node
    assert st == before


def test_growth_at_fourteenth_element():
    st = new_table(1.0)
    for key in range(13):
        insert(st, key)
    assert st["bucket_count"] == 13 and st["element_count"] == 13
    insert(st, 13)
    assert st["bucket_count"] == 29
    assert st["next_resize"] == 29
    assert st["element_count"] == 14
    for key in range(14):
        node, inserted = insert(st, key)
        assert inserted is False


def test_collision_chain_links_after_before_begin():
    st = new_table(1.0)
    insert(st, 3)
    insert(st, 16)  # 16 % 13 == 3
    assert _list_keys(st) == [16, 3]
    assert st["buckets"][3] == BB
    insert(st, 29)  # 29 % 13 == 3
    assert _list_keys(st) == [29, 16, 3]
    node, inserted = insert(st, 16)
    assert inserted is False
    assert st["nodes"][node]["key"] == 16


def test_case_b_updates_old_head_bucket_slot():
    st = new_table(1.0)
    first, _ = insert(st, 1)
    second, _ = insert(st, 2)  # bucket 2 empty: new list head
    assert st["head"] == second
    assert _list_keys(st) == [2, 1]
    assert st["buckets"][2] == BB
    assert st["buckets"][1] == second  # predecessor of key 1's node


def test_need_rehash_probed_points():
    def probe(mlf, nr, bkt, elt, ins=1):
        st = {"max_load_factor": mlf, "next_resize": nr}
        grow, count = need_rehash(st, bkt, elt, ins)
        return grow, count, st["next_resize"]

    assert probe(1.0, 0, 1, 0) == (True, 13, 13)
    assert probe(1.0, 0, 13, 13) == (True, 29, 29)
    assert probe(1.0, 7, 1, 1) == (False, 0, 7)      # under cached threshold
    assert probe(1.0, 3, 100, 50) == (False, 0, 100)  # min_bkts below count
    assert probe(0.25, 0, 31, 57) == (True, 241, 60)
    assert probe(1.0, 0, 2, 12) == (True, 17, 17)     # strict prime step
    assert probe(0.5, 0, 3, 1) == (True, 23, 11)


def test_zero_count_linear_scan():
    st = new_table(1.0)
    st["bucket_count"] = 13
    st["buckets"] = [None] * 13
    st["buckets_ptr"] = 0x10030
    st["alloc_next"] = 0x100A0
    # keys 5, 18, 31 all hash to bucket 5; list order 5, 18, 31
    st["nodes"] = {
        0x10000: {"next": 0x10010, "key": 5},
        0x10010: {"next": 0x10020, "key": 18},
        0x10020: {"next": None, "key": 31},
    }
    st["buckets"][5] = BB
    st["head"] = 0x10000
    st["element_count"] = 0  # forged: count disagrees with the list
    node, inserted = insert(st, 18)
    assert (node, inserted) == (0x10010, False)
    node, inserted = insert(st, 44)
    assert inserted is True
    assert st["element_count"] == 1  # 0 + 1, as the binary counts


def test_mlf_half_growth_shape():
    st = new_table(0.5)
    for key in range(25):
        insert(st, key)
    assert st["bucket_count"] == 97
    assert st["element_count"] == 25


def test_huge_keys():
    st = new_table(1.0)
    big = (1 << 64) - 1
    node, inserted = insert(st, big)
    assert inserted is True
    again, inserted = insert(st, big)
    assert (again, inserted) == (node, False)
    insert(st, 1 << 63)
    assert _list_keys(st)[0] == (1 << 63)  # newest empty-bucket head


def test_key_out_of_range_raises():
    st = new_table(1.0)
    for bad in (-1, 1 << 64):
        try:
            insert(st, bad)
        except ValueError:
            continue
        raise AssertionError("expected ValueError for %r" % (bad,))


def test_packet_records_match_model():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task"] == "RE-001"
    assert records["artifact_sha256"] == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    starts = [w["start"] for w in records["windows"]]
    assert "0x5f90bb0" in starts and "0x5da04d0" in starts and "0x5f90b86" in starts
    assert records["census"]["0x5f90bb0"]["direct_calls"] == ["0x5f90f9c", "0x5f91217"]
    assert records["twin_comparison"]["window_bytes"] == 450


def test_packet_excerpts_present():
    body = (PACKET_DIR / "function_0x5f90bb0.txt").read_text()
    assert "5f90bb0:" in body and "63f0ef0" in body and "5f90d66" in body
    rehash = (PACKET_DIR / "function_0x5da04d0.txt").read_text()
    assert "5da04d0:" in rehash and "63f0a90" in rehash
    cleanup = (PACKET_DIR / "function_0x5f90b86.txt").read_text()
    assert "5f90b86:" in cleanup and "63f0d80" in cleanup


TESTS = [
    test_first_insert_grows_and_links_as_head,
    test_duplicate_returns_existing_node_and_changes_nothing,
    test_growth_at_fourteenth_element,
    test_collision_chain_links_after_before_begin,
    test_case_b_updates_old_head_bucket_slot,
    test_need_rehash_probed_points,
    test_zero_count_linear_scan,
    test_mlf_half_growth_shape,
    test_huge_keys,
    test_key_out_of_range_raises,
    test_packet_records_match_model,
    test_packet_excerpts_present,
]


def main():
    for test in TESTS:
        test()
    print("%d tests passed" % len(TESTS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
