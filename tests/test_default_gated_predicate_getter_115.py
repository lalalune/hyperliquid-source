"""Tests for the node #115 default-gated predicate getter model.

Covers the getter's default and override arms, the masking quirk,
and the default implementation, plus packet checks on
research/work-items/RE-001-default-gated-predicate-getter-115.
Runs under plain python3 (pytest is not installed on this VM):

  python3 tests/test_default_gated_predicate_getter_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from default_gated_predicate_getter_115 import (  # noqa: E402
    DEFAULT_SLOT,
    default_predicate,
    predicate_getter,
)

PACKET_DIR = Path(__file__).resolve().parents[1] / \
    "research" / "work-items" / "RE-001-default-gated-predicate-getter-115"


def member(slot, field30=0x1000):
    return {"field950": {"slot": slot}, "field30": field30}


def test_default_arm_stores_zero_and_returns_one():
    out = [None]
    assert predicate_getter({"field788": member(DEFAULT_SLOT)}, out) == 1
    assert out[0] == 0


def test_default_predicate_returns_zero():
    assert default_predicate({"slot": DEFAULT_SLOT}, 0x1234) == 0


def test_override_zero_and_one_pass_through():
    for value in (0, 1):
        out = [None]
        seen = {}
        def override(obj, arg, value=value, seen=seen):
            seen["arg"] = arg
            return value
        assert predicate_getter(
            {"field788": member(override)}, out) == 1
        assert out[0] == value


def test_override_receives_obj_and_field30_plus_0x40():
    seen = {}
    def override(obj, arg):
        seen["obj"] = obj
        seen["arg"] = arg
        return 1
    m = member(override, field30=0x2000)
    out = [None]
    predicate_getter({"field788": m}, out)
    assert seen["obj"] is m["field950"]
    assert seen["arg"] == 0x2040


def test_override_argument_wraps_at_64_bits():
    seen = {}
    def override(obj, arg):
        seen["arg"] = arg
        return 1
    out = [None]
    predicate_getter(
        {"field788": member(override, field30=(1 << 64) - 0x20)}, out)
    assert seen["arg"] == 0x20


def test_override_return_masked_to_low_byte():
    out = [None]
    predicate_getter(
        {"field788": member(lambda obj, arg: 0x1AB)}, out)
    assert out[0] == 0xAB
    out = [None]
    predicate_getter(
        {"field788": member(lambda obj, arg: 0x100)}, out)
    assert out[0] == 0


def test_missing_field_raises():
    for outer in ({}, {"field788": {}},
                  {"field788": {"field950": {}}}):
        try:
            predicate_getter(outer, [None])
        except KeyError:
            pass
        else:
            raise AssertionError("expected KeyError for %r" % (outer,))


def test_default_arm_needs_no_field30():
    # The binary reads [member + 0x30] only on the override arm, so
    # the default arm succeeds without it.
    out = [None]
    assert predicate_getter(
        {"field788": {"field950": {"slot": DEFAULT_SLOT}}}, out) == 1
    assert out[0] == 0


def test_missing_field30_on_override_arm_raises():
    def override(obj, arg):
        return 1
    try:
        predicate_getter(
            {"field788": {"field950": {"slot": override}}}, [None])
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for a missing field30")


def test_packet_records():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    assert records["artifact"]["sha256"] == \
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    starts = [w["start"] for w in records["windows"]]
    assert starts == ["0x5eeb7a0", "0x5d89610"]
    # Semantic records only: no per-instruction mnemonic list.
    assert "instructions" not in records
    assert "mnemonics" not in records
    for name in ("function_0x5eeb7a0.txt", "function_0x5d89610.txt"):
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
