"""Tests for tools/rdx_getters_115.py (node #115 rdx-arg getters).

Pytest-style test functions with a plain-python ``__main__`` runner
(pytest is not installed in this environment), printing
ALL TESTS PASSED only when every test passes.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import rdx_getters_115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research"
          / "work-items" / "RE-001-rdx-getters-115")
MASK64 = (1 << 64) - 1


def test_leaf550_nested():
    assert m.leaf550({"slot68": {"field_e0": 42}}) == 42


def test_getter_c_ignores_outer_and_returns_one():
    out = [None]
    assert m.getter_c("ignored-outer", out,
                      {"slot68": {"field_e0": 7}}) == 1
    assert out[0] == 7
    out = [None]
    assert m.getter_c(None, out, {"slot68": {"field_e0": 7}}) == 1
    assert out[0] == 7


def test_leaf560_empty_calls_refresh_and_returns_minus_one():
    calls = []
    assert m.leaf560({"head_first": None}, calls.append) == MASK64
    assert len(calls) == 1


def test_leaf560_nonempty_calls_refresh_and_returns_payload():
    calls = []
    obj = {"head_first": {"payload": 99}}
    assert m.leaf560(obj, calls.append) == 99
    assert len(calls) == 1


def test_getter_d_passthrough():
    out = [None]
    calls = []
    assert m.getter_d("ignored", out, {"head_first": None},
                      calls.append) == 1
    assert out[0] == MASK64
    assert len(calls) == 1


def test_getter_e_positive_zero_negative():
    out = [None]
    assert m.getter_e("ignored", out, {"count": 5, "ptr": 1234}) == 1
    assert out[0] == 1234
    assert m.getter_e("ignored", out, {"count": 0, "ptr": 1234}) == 1
    assert out[0] == 0
    assert m.getter_e("ignored", out, {"count": -3, "ptr": 1234}) == 1
    assert out[0] == 0


def test_leaf610_raw_quirk():
    # Positive: low byte forced to 1, upper bits kept.
    assert m.leaf610_raw(0x12345678) == 0x12345601
    assert m.leaf610_raw(1) == 1
    # Zero: low byte 0, upper bits kept (here all zero).
    assert m.leaf610_raw(0) == 0
    # Negative: low byte 0, upper bits kept from the 32-bit pattern.
    assert m.leaf610_raw(-1) == 0xFFFFFF00
    assert m.leaf610_raw(-256) == 0xFFFFFF00


def test_getter_f_masks_to_clean_flag():
    out = [None]
    assert m.getter_f("ignored", out, 0x12345678) == 1
    assert out[0] == 1
    assert m.getter_f("ignored", out, 0) == 1
    assert out[0] == 0
    assert m.getter_f("ignored", out, -1) == 1
    assert out[0] == 0
    assert m.getter_f("ignored", out, -2147483648) == 1
    assert out[0] == 0


def test_packet_records():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    assert records["node"] == 115
    assert len(records["windows"]) == 7
    starts = {w["start"] for w in records["windows"]}
    assert starts == {"0x5eeb6c0", "0x5eeb6e0", "0x5eeb700",
                      "0x5eeb720", "0x5e4b550", "0x5e4b560",
                      "0x5fc9610"}
    assert len(records["getter_records"]) == 4
    assert len(records["callee_records"]) == 5
    assert records["census"]["0x5e4b550"]["direct_calls"] == [
        "0x5dd1aff", "0x5e4ef75", "0x5e697f0", "0x5eeb6cb"]
    assert records["census"]["0x5fc9610"]["direct_calls"][11] == "0x5eeb72f"
    assert (PACKET / "MANIFEST.sha256").exists()
    assert (PACKET / "README.md").exists()


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]


if __name__ == "__main__":
    for test in TESTS:
        test()
    print("ALL TESTS PASSED (%d tests)" % len(TESTS))
