"""Tests for tools/sibling_getters_115.py (node #115 sibling getters).

Runs under pytest when available, and under plain python3 via the
``__main__`` runner below (this VM has no pytest installed).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from sibling_getters_115 import (  # noqa: E402
    HEADER,
    field_load,
    getter_field,
    getter_list_sum,
    list_sum,
)

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-sibling-getters-115"
MASK64 = (1 << 64) - 1


def make_list(payloads):
    """A header-terminated list over payloads in walk order."""
    header = {"first": HEADER}
    nodes = {}
    prev = None
    for i, payload in enumerate(payloads):
        node_id = "n%d" % i
        nodes[node_id] = {"payload": payload, "next": HEADER}
        if prev is None:
            header["first"] = node_id
        else:
            nodes[prev]["next"] = node_id
        prev = node_id
    return header, nodes


def test_empty_list_returns_zero():
    header, nodes = make_list([])
    assert list_sum(header, nodes, lambda p: p) == 0


def test_single_and_multiple_nodes_sum_in_order():
    seen = []
    def per_element(payload):
        seen.append(payload)
        return payload
    header, nodes = make_list([5, 7, 11])
    assert list_sum(header, nodes, per_element) == 23
    assert seen == [5, 7, 11]


def test_list_sum_wraps_64_bit():
    header, nodes = make_list([MASK64, 2])
    assert list_sum(header, nodes, lambda p: p) == 1


def test_per_element_return_added_not_payload():
    header, nodes = make_list(["a", "b"])
    values = {"a": 100, "b": 23}
    assert list_sum(header, nodes, lambda p: values[p]) == 123


def test_non_terminating_chain_raises():
    header = {"first": "n0"}
    nodes = {"n0": {"payload": 1, "next": "n0"}}
    try:
        list_sum(header, nodes, lambda p: p)
    except ValueError:
        pass
    else:
        raise AssertionError("cyclic chain did not raise")


def test_field_load_returns_plus_0x18_qword():
    assert field_load({"field_0x18": 0x123456789ABCDEF0}) == 0x123456789ABCDEF0
    assert field_load({"field_0x18": MASK64 + 5}) == 4


def test_list_sum_getter_adds_base_and_returns_one():
    header, nodes = make_list([10, 20])
    stored, ret = getter_list_sum(5, header, nodes, lambda p: p)
    assert (stored, ret) == (35, 1)


def test_list_sum_getter_empty_list_stores_base_only():
    header, nodes = make_list([])
    stored, ret = getter_list_sum(42, header, nodes, lambda p: p)
    assert (stored, ret) == (42, 1)


def test_list_sum_getter_addition_wraps():
    header, nodes = make_list([1])
    stored, ret = getter_list_sum(MASK64, header, nodes, lambda p: p)
    assert (stored, ret) == (0, 1)


def test_field_getter_adds_base_and_returns_one():
    stored, ret = getter_field(7, {"field_0x18": 3})
    assert (stored, ret) == (10, 1)


def test_field_getter_addition_wraps():
    stored, ret = getter_field(MASK64, {"field_0x18": 9})
    assert (stored, ret) == (8, 1)


def test_packet_records():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["task"] == "RE-001"
    assert records["artifact"]["sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["census"]["direct_calls_to_0x5f133e0"] == 1
    assert records["census"]["direct_calls_to_0x5f13420"] == 1
    assert records["census"]["direct_calls_to_0x5f0e2d0"] == 11
    assert [w["start"] for w in records["windows"]] == [
        "0x5eeb490", "0x5eeb4d0", "0x5f133e0", "0x5f13420"]
    assert records["per_element_callee"]["function"] == "0x5f0e2d0"
    for name in ("function_0x5eeb490.txt", "function_0x5eeb4d0.txt",
                 "function_0x5f133e0.txt", "function_0x5f13420.txt"):
        text = (PACKET / name).read_text()
        assert "endbr64" in text
        assert "placeholder" not in text


TESTS = [
    test_empty_list_returns_zero,
    test_single_and_multiple_nodes_sum_in_order,
    test_list_sum_wraps_64_bit,
    test_per_element_return_added_not_payload,
    test_non_terminating_chain_raises,
    test_field_load_returns_plus_0x18_qword,
    test_list_sum_getter_adds_base_and_returns_one,
    test_list_sum_getter_empty_list_stores_base_only,
    test_list_sum_getter_addition_wraps,
    test_field_getter_adds_base_and_returns_one,
    test_field_getter_addition_wraps,
    test_packet_records,
]


def main():
    for test in TESTS:
        test()
        print("ok", test.__name__)
    print("all %d tests passed" % len(TESTS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
