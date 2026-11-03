"""Tests for tools/two_flag_lazy_init_115.py (node #115 two-flag
lazy-init variant 0x605e8a0 with its callback 0x606a890 and wrapper
0x605e8f0).

Run with pytest, or directly: ``python3 tests/test_two_flag_lazy_init_115.py``
prints ALL TESTS PASSED when every check passes.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from two_flag_lazy_init_115 import callback, variant_init, wrapper

PACKET_DIR = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / "RE-001-two-flag-lazy-init-115"


def make_holder(flag10=0, flag11=0, inner=None, cb_arg=30):
    if inner is None:
        inner = {"first": "obj", "field20": 0, "field10": 100}
    return {"inner": inner, "cb_arg": cb_arg,
            "flag10": flag10, "flag11": flag11}


def lazy_init_stub(calls):
    """Stand-in for 0x605e860 as mapped by #2244: records the call
    and sets flag10, mirroring its documented contract."""

    def fn(holder):
        calls.append("lazy_init")
        holder["flag10"] = 1

    return fn


def callback_recorder(calls):
    def on_170(obj):
        calls.append("on_170")

    def delegate(obj):
        calls.append("delegate")

    def fn(inner, amount):
        calls.append(("callback", amount))
        callback(inner, amount, on_170, delegate)

    return fn


def test_flag10_zero_calls_lazy_init_then_flag11():
    calls = []
    holder = make_holder(flag10=0)
    variant_init(holder, lazy_init_stub(calls),
                 callback_recorder(calls))
    assert calls[0] == "lazy_init", calls
    assert ("callback", 30) in calls, calls
    assert holder["flag10"] == 1 and holder["flag11"] == 1


def test_flag10_nonzero_skips_lazy_init_but_runs_flag11():
    calls = []
    holder = make_holder(flag10=1)
    variant_init(holder, lazy_init_stub(calls),
                 callback_recorder(calls))
    assert "lazy_init" not in calls, calls
    assert ("callback", 30) in calls, calls
    assert holder["flag11"] == 1


def test_inner_none_returns_flag11_untouched():
    for flag10 in (0, 1):
        calls = []
        holder = make_holder(flag10=flag10)
        holder["inner"] = None
        variant_init(holder, lazy_init_stub(calls),
                     callback_recorder(calls))
        assert holder["flag11"] == 0, holder
        assert not any(isinstance(c, tuple) for c in calls), calls


def test_flag11_nonzero_returns_callback_not_called():
    calls = []
    holder = make_holder(flag10=1, flag11=1)
    variant_init(holder, lazy_init_stub(calls),
                 callback_recorder(calls))
    assert not any(isinstance(c, tuple) for c in calls), calls
    assert holder["flag11"] == 1


def test_callback_skipped_but_flag11_set():
    calls = []
    inner = {"first": None, "field20": 0, "field10": 50}
    holder = make_holder(flag10=1, inner=inner)
    variant_init(holder, lazy_init_stub(calls),
                 callback_recorder(calls))
    assert not any(isinstance(c, tuple) for c in calls), calls
    assert holder["flag11"] == 1
    assert inner["field10"] == 50


def test_callback_via_field20_without_first():
    calls = []
    inner = {"first": None, "field20": 7, "field10": 50}
    holder = make_holder(flag10=1, inner=inner)
    variant_init(holder, lazy_init_stub(calls),
                 callback_recorder(calls))
    assert ("callback", 30) in calls, calls
    assert holder["flag11"] == 1


def test_callback_field20_arm_calls_on_170_no_sub():
    calls = []
    obj = {"first": "x", "field20": 3, "field10": 100}
    callback(obj, 30, lambda o: calls.append("on_170"),
             lambda o: calls.append("delegate"))
    assert calls == ["on_170", "delegate"], calls
    assert obj["field10"] == 100


def test_callback_null_first_skips_sub_but_delegates():
    calls = []
    obj = {"first": None, "field20": 0, "field10": 100}
    callback(obj, 30, lambda o: calls.append("on_170"),
             lambda o: calls.append("delegate"))
    assert calls == ["delegate"], calls
    assert obj["field10"] == 100


def test_callback_subtract_wraps_and_delegates():
    calls = []
    obj = {"first": "x", "field20": 0, "field10": 5}
    callback(obj, 9, lambda o: calls.append("on_170"),
             lambda o: calls.append("delegate"))
    assert calls == ["delegate"], calls
    assert obj["field10"] == (5 - 9) & ((1 << 64) - 1)


def test_wrapper_forwards_holder():
    calls = []
    holder = make_holder(flag10=0)
    wrapper(holder, lazy_init_stub(calls), callback_recorder(calls))
    assert calls[0] == "lazy_init", calls
    assert holder["flag11"] == 1


def test_flag_range_guard():
    for bad in (-1, 256):
        holder = make_holder(flag10=bad)
        try:
            variant_init(holder, lazy_init_stub([]),
                         callback_recorder([]))
        except ValueError:
            pass
        else:
            raise AssertionError("flag %r not rejected" % bad)


def test_packet_checks():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    assert records["artifact_sha256"] == \
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    assert [w["name"] for w in records["windows"]] == \
        ["variant", "wrapper", "callback"]
    assert len(records["caller_records"]) == 5
    for name in ("function_0x605e8a0.txt", "function_0x605e8f0.txt",
                 "function_0x606a890.txt", "frames.txt",
                 "relocations.txt", "verify.py", "census.py",
                 "export_excerpts.py", "MANIFEST.sha256", "README.md"):
        assert (PACKET_DIR / name).exists(), name


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]


def main():
    for fn in TESTS:
        fn()
    print("ALL TESTS PASSED (%d tests)" % len(TESTS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
