"""Tests for tools/element_prepare_115.py (node #115 element prepare).

Runs under pytest when available, and under plain python3 via the
``__main__`` runner below (this VM has no pytest installed).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from element_prepare_115 import count_total, element_prepare  # noqa: E402

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-element-prepare-115"


def make_holder():
    return {"counter": 0, "ready": 0}


def make_element(name):
    return {"name": name}


def run(collection):
    holder = make_holder()
    seen = []

    def prepare(element):
        seen.append(element["name"])

    log = element_prepare(holder, collection, prepare)
    return holder, seen, log


def test_empty_total_sets_ready_and_releases_guard():
    holder, seen, log = run({"field_0x00": 0, "first": [], "second": []})
    assert seen == []
    assert holder == {"counter": 0, "ready": 1}
    assert log == [("acquire", 9), ("release",)]


def test_first_array_only():
    elements = [make_element("a"), make_element("b")]
    holder, seen, log = run(
        {"field_0x00": 2, "first": elements, "second": []})
    assert seen == ["a", "b"]
    assert holder["counter"] == 2 and holder["ready"] == 1
    assert all(e["zeroed_0xa88"] for e in elements)


def test_second_array_run_past_index_seven():
    # field_0x00 == 8 plus a 3-long second array: total 11, indices
    # 0..7 from the first array, 8..10 from the second array.
    first = [make_element("f%d" % i) for i in range(8)]
    second = [make_element("s%d" % i) for i in range(3)]
    holder, seen, log = run(
        {"field_0x00": 8, "first": first, "second": second})
    assert seen == ["f%d" % i for i in range(8)] + ["s0", "s1", "s2"]
    assert holder["counter"] == 11


def test_index_eight_boundary():
    first = [make_element("f%d" % i) for i in range(8)]
    second = [make_element("s0")]
    holder, seen, log = run(
        {"field_0x00": 8, "first": first, "second": second})
    assert seen[-1] == "s0"
    assert len(seen) == 9


def test_call_order_and_counter():
    first = [make_element("x"), make_element("y"), make_element("z")]
    holder, seen, log = run(
        {"field_0x00": 3, "first": first, "second": []})
    assert seen == ["x", "y", "z"]
    assert holder["counter"] == 3


def test_counter_wraps_32_bit():
    holder = {"counter": 0xFFFFFFFF, "ready": 0}
    element = make_element("only")
    element_prepare(holder,
                    {"field_0x00": 1, "first": [element], "second": []},
                    lambda e: None)
    assert holder["counter"] == 0


def test_negative_total_raises():
    # field_0x00 == 0 with an empty second array is total 0 (fine);
    # a negative total needs a field that wraps below zero: use the
    # 64-bit two's-complement form of -1 with an empty second array.
    try:
        run({"field_0x00": (1 << 64) - 1, "first": [], "second": []})
    except ValueError:
        pass
    else:
        raise AssertionError("negative total did not raise")


def test_count_formula():
    assert count_total({"field_0x00": 8, "first": [], "second": [1, 2]}) == 10
    assert count_total({"field_0x00": 0, "first": [], "second": []}) == 0


def test_packet_records():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["task"] == "RE-001"
    assert records["windows"][0]["start"] == "0x5f13310"
    assert records["windows"][0]["end"] == "0x5f133da"
    assert records["census"]["direct_calls_to_0x5f13310"] == 2
    assert records["call_sites"][2]["sites"] == ["0x5f1337c"]
    assert records["collection"]["count_rule"].startswith("total = ")


def _main():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok %s" % name)
    print("%d tests passed" % len(tests))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
