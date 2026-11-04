"""Tests for the node #115 chain-length getter model.

Covers the counter, the forwarding stub, and the getter end to end,
plus packet checks on research/work-items/RE-001-chain-length-getter-115.
Runs under plain python3 (pytest is not installed on this VM):

  python3 tests/test_chain_length_getter_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from chain_length_getter_115 import (  # noqa: E402
    chain_length,
    chain_length_getter,
    forwarding_stub,
)

PACKET_DIR = Path(__file__).resolve().parents[1] / \
    "research" / "work-items" / "RE-001-chain-length-getter-115"


def test_self_loop_returns_zero():
    assert chain_length("h", {"h": "h"}) == 0


def test_two_node_cycle_returns_one():
    assert chain_length("h", {"h": "a", "a": "h"}) == 1


def test_four_node_cycle_returns_three():
    chain = {"h": "a", "a": "b", "b": "c", "c": "h"}
    assert chain_length("h", chain) == 3


def test_long_chain_counts_non_head_nodes():
    nodes = ["n%d" % i for i in range(100)]
    chain = {"h": nodes[0]}
    for cur, nxt in zip(nodes, nodes[1:] + ["h"]):
        chain[cur] = nxt
    assert chain_length("h", chain) == 100


def test_stub_forwards_counter_result():
    member = {"field28": "h"}
    chain = {"h": "a", "a": "h"}
    assert forwarding_stub(member, chain) == 1


def test_getter_end_to_end_stores_and_returns_one():
    outer = {"field788": {"field28": "h"}}
    chain = {"h": "a", "a": "b", "b": "h"}
    out = [None]
    assert chain_length_getter(outer, out, chain) == 1
    assert out[0] == 2


def test_getter_reads_field788_then_field28():
    outer = {"field788": {"field28": "x"}}
    chain = {"x": "x"}
    out = [None]
    assert chain_length_getter(outer, out, chain) == 1
    assert out[0] == 0


def test_non_returning_cycle_raises():
    chain = {"h": "a", "a": "b", "b": "a"}
    try:
        chain_length("h", chain)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a non-returning cycle")


def test_missing_link_raises():
    try:
        chain_length("h", {"h": "ghost"})
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for a missing link")


def test_packet_records():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    starts = [w["start"] for w in records["windows"]]
    assert starts == ["0x5eeb610", "0x5d8c9a0", "0x5f70180"]
    # Semantic records only: no per-instruction mnemonic list.
    assert "instructions" not in records
    assert "mnemonics" not in records
    for name in ("function_0x5eeb610.txt", "function_0x5d8c9a0.txt",
                 "function_0x5f70180.txt"):
        assert (PACKET_DIR / name).exists()


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for test in tests:
        test()
    print("%d tests passed" % len(tests))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
