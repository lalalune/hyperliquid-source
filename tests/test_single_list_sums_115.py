"""Tests for the node #115 single-list field sums (RE-001).

Runs under pytest when available; also runnable directly with plain
python3 (pytest is not installed on this VM), via the __main__ runner
below. Expectations are grounded in the verbatim excerpts in
research/work-items/RE-001-single-list-sums-115/.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from single_list_sums_115 import (  # noqa: E402
    MASK64,
    Header,
    Inner,
    Node,
    Outer,
    composite,
    getter_a,
    getter_b,
    link,
    sum_a70,
    sum_a78,
)


def make_list(pairs):
    header = Header()
    nodes = [Node({"a70": a70, "a78": a78}) for a70, a78 in pairs]
    link(header, nodes)
    return header


def make_outer(pairs, record_a70=0, record_a78=0, field30=0):
    inner = Inner(make_list(pairs),
                  {"a70": record_a70, "a78": record_a78},
                  field30)
    return Outer(inner)


def test_empty_list_sums_to_zero():
    header = Header()
    assert sum_a70(header) == 0
    assert sum_a78(header) == 0


def test_single_node_sums():
    header = make_list([(7, 11)])
    assert sum_a70(header) == 7
    assert sum_a78(header) == 11


def test_multiple_nodes_sum_each_field_separately():
    header = make_list([(1, 100), (2, 200), (3, 300)])
    assert sum_a70(header) == 6
    assert sum_a78(header) == 600


def test_sums_wrap_at_64_bits():
    header = make_list([(MASK64, 5), (2, MASK64)])
    assert sum_a70(header) == 1
    assert sum_a78(header) == 4


def test_getters_store_sum_and_return_one():
    outer = make_outer([(4, 9), (6, 1)])
    assert getter_a(outer) == (10, 1)
    assert getter_b(outer) == (10, 1)


def test_composite_positive_remainder():
    # base = 100 + A(10) + G(0) = 110; B = 10, D = 5 -> doubled 30.
    outer = make_outer([(4, 9), (6, 1)], record_a70=100, record_a78=5)
    assert composite(outer, lambda arg: 0) == (80, 1)


def test_composite_zero_when_doubled_reaches_base():
    outer = make_outer([(50, 50)], record_a70=0, record_a78=50)
    # base = 0 + 50 + 0 = 50; doubled = 2*(50+50) = 200 >= 50.
    assert composite(outer, lambda arg: 0) == (0, 1)


def test_composite_includes_g_callee_and_distinguished_field():
    outer = make_outer([(10, 10)], record_a70=100, record_a78=7)
    # base = 100 + 10 + 40 = 150; doubled = 2*(10+7) = 34.
    assert composite(outer, lambda arg: 40) == (116, 1)


def test_composite_g_receives_field30_plus_0x40():
    seen = []
    outer = make_outer([], record_a70=0, record_a78=0, field30=0x1000)
    composite(outer, lambda arg: seen.append(arg) or 0)
    assert seen == [0x1040]


def test_composite_literal_wrap_semantics():
    # Doubled wraps to 0, which is < base, so the literal result is base.
    outer = make_outer([(0, 1 << 63)], record_a70=10, record_a78=0)
    assert composite(outer, lambda arg: 0) == (10, 1)


def test_non_terminating_chain_raises():
    header = Header()
    a = Node({"a70": 1, "a78": 1})
    b = Node({"a70": 2, "a78": 2})
    header.first = a
    a.next = b
    b.next = a  # cycle that never reaches the header
    try:
        sum_a70(header)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a cyclic chain")


def test_packet_records_parse_and_excerpts_exist():
    base = os.path.join(os.path.dirname(__file__), "..",
                        "research", "work-items",
                        "RE-001-single-list-sums-115")
    with open(os.path.join(base, "records.json")) as fh:
        records = json.load(fh)
    assert records["task"] == "RE-001"
    assert records["artifact"]["sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    for name in ("window_a_0x5f13060.txt", "window_b_0x5f13100.txt",
                 "getter_a_0x5eeb510.txt", "getter_b_0x5eeb540.txt",
                 "composite_0x5eeb570.txt"):
        path = os.path.join(base, name)
        assert os.path.exists(path), name
        with open(path) as fh:
            text = fh.read()
        assert "endbr64" in text, name


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]

if __name__ == "__main__":
    failures = 0
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report and continue
            failures += 1
            print(f"FAIL {test.__name__}: {exc}")
        else:
            print(f"PASS {test.__name__}")
    print(f"{len(TESTS) - failures}/{len(TESTS)} tests passed")
    sys.exit(1 if failures else 0)
