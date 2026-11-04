"""Tests for tools/predicate_gate_115.py (node #115 predicate gate).

Runs under pytest when available, and under plain python3 via the
``__main__`` runner below (this VM has no pytest installed).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from predicate_gate_115 import (  # noqa: E402
    branch_compare_caller_5ddafe7,
    branch_compare_caller_5de860e,
    branch_gate_caller_5e8d1e6,
    flag_compare,
    gate,
    getter,
)

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-predicate-gate-115"


def rec(flag=0, value=0, threshold=0, link_value=None):
    return {"flag": flag, "value": value, "threshold": threshold,
            "link_value": link_value}


def test_flag_zero_always_compares():
    assert flag_compare(rec(flag=0, value=10, threshold=10)) == 1
    assert flag_compare(rec(flag=0, value=10, threshold=11)) == 0
    assert flag_compare(rec(flag=0, value=-3, threshold=-5)) == 1
    assert flag_compare(rec(flag=0, value=-3, threshold=-2)) == 0


def test_flag_nonzero_positive_value_returns_flag_byte():
    assert flag_compare(rec(flag=1, value=5, threshold=99)) == 1
    assert flag_compare(rec(flag=2, value=5, threshold=99)) == 2
    assert flag_compare(rec(flag=0x80, value=1, threshold=99)) == 0x80


def test_flag_nonzero_nonpositive_value_compares():
    assert flag_compare(rec(flag=1, value=0, threshold=0)) == 1
    assert flag_compare(rec(flag=1, value=0, threshold=1)) == 0
    assert flag_compare(rec(flag=3, value=-1, threshold=-1)) == 1
    assert flag_compare(rec(flag=3, value=-1, threshold=0)) == 0


def test_gate_mismatch_returns_one():
    assert gate(rec(flag=0, value=7, threshold=99, link_value=8)) == 1


def test_gate_match_delegates_to_compare():
    assert gate(rec(flag=0, value=7, threshold=7, link_value=7)) == 1
    assert gate(rec(flag=0, value=7, threshold=8, link_value=7)) == 0
    assert gate(rec(flag=2, value=7, threshold=99, link_value=7)) == 2


def test_gate_sign_extension_equality():
    # Own value is a signed 32-bit; -1 sign-extends to 2**64 - 1.
    assert gate(rec(flag=0, value=-1, threshold=-1,
                    link_value=(1 << 64) - 1)) == 1
    assert gate(rec(flag=0, value=-1, threshold=0,
                    link_value=(1 << 64) - 1)) == 0
    # A large positive qword can never equal a sign-extended int32
    # except through the 2**64-1 pattern above.
    assert gate(rec(flag=0, value=5, threshold=5,
                    link_value=(1 << 63))) == 1


def test_gate_missing_link_raises():
    try:
        gate(rec(flag=0, value=1, threshold=1, link_value=None))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a missing link")


def test_getter_stores_raw_byte_and_returns_one():
    assert getter(rec(flag=0, value=4, threshold=4)) == (1, 1)
    assert getter(rec(flag=2, value=4, threshold=99)) == (2, 1)
    assert getter(rec(flag=0, value=4, threshold=5)) == (0, 1)


def test_consumer_branches():
    assert branch_gate_caller_5e8d1e6(1) == "skip"
    assert branch_gate_caller_5e8d1e6(0) == "continue"
    assert branch_compare_caller_5ddafe7(0) == "away"
    assert branch_compare_caller_5ddafe7(2) == "proceed"
    assert branch_compare_caller_5de860e(0) == "away"
    assert branch_compare_caller_5de860e(1) == "proceed"


def test_packet_records():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["task"] == "RE-001"
    assert records["artifact"]["sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    starts = [w["start"] for w in records["windows"]]
    assert starts == ["0x5f132a0", "0x5f132c0", "0x5eeb460"]
    assert records["census"]["direct_calls_to_0x5f132a0"] == 3
    assert records["census"]["direct_calls_to_0x5f132c0"] == 1
    assert records["census"]["tail_jumps_to_0x5f132a0"] == 1
    for name in ("function_0x5f132a0.txt", "function_0x5f132c0.txt",
                 "function_0x5eeb460.txt"):
        text = (PACKET / name).read_text()
        assert "endbr64" in text
        assert "placeholder" not in text


TESTS = [
    test_flag_zero_always_compares,
    test_flag_nonzero_positive_value_returns_flag_byte,
    test_flag_nonzero_nonpositive_value_compares,
    test_gate_mismatch_returns_one,
    test_gate_match_delegates_to_compare,
    test_gate_sign_extension_equality,
    test_gate_missing_link_raises,
    test_getter_stores_raw_byte_and_returns_one,
    test_consumer_branches,
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
