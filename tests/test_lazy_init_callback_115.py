"""Tests for tools/lazy_init_callback_115.py (node #115 lazy-init
0x605e860 with its callback 0x606a110).

Run with pytest, or directly: ``python3 tests/test_lazy_init_callback_115.py``
prints ALL TESTS PASSED when every check passes.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from lazy_init_callback_115 import callback, lazy_init

PACKET_DIR = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / "RE-001-lazy-init-callback-115"


def make_holder(flag10=0, inner=None, cb_arg=30):
    if inner is None:
        inner = {"first": "obj", "field20": 0, "field18": 100}
    return {"inner": inner, "cb_arg": cb_arg, "flag10": flag10}


def test_inner_none_returns_flag_untouched():
    holder = make_holder(flag10=0)
    holder["inner"] = None
    lazy_init(holder)
    assert holder["flag10"] == 0, holder


def test_flag_nonzero_returns_flag_untouched():
    inner = {"first": "obj", "field20": 0, "field18": 100}
    holder = make_holder(flag10=7, inner=inner)
    lazy_init(holder)
    assert holder["flag10"] == 7
    assert inner["field18"] == 100


def test_first_nonzero_subtracts_and_sets_flag():
    inner = {"first": "obj", "field20": 0, "field18": 100}
    holder = make_holder(flag10=0, inner=inner, cb_arg=30)
    lazy_init(holder)
    assert inner["field18"] == 70
    assert holder["flag10"] == 1


def test_both_zero_skips_callback_but_sets_flag():
    inner = {"first": None, "field20": 0, "field18": 50}
    holder = make_holder(flag10=0, inner=inner)
    lazy_init(holder)
    assert inner["field18"] == 50
    assert holder["flag10"] == 1


def test_field20_arm_runs_callback_without_store():
    # The callback's own null arm: [inner] == 0 but [inner + 0x20]
    # != 0, so lazy-init calls it and it returns without storing.
    inner = {"first": None, "field20": 7, "field18": 50}
    holder = make_holder(flag10=0, inner=inner)
    lazy_init(holder)
    assert inner["field18"] == 50
    assert holder["flag10"] == 1


def test_callback_direct_subtract_and_wrap():
    inner = {"first": "obj", "field20": 0, "field18": 5}
    callback(inner, 9)
    assert inner["field18"] == (5 - 9) & ((1 << 64) - 1)


def test_callback_direct_null_first_no_store():
    inner = {"first": None, "field20": 7, "field18": 50}
    callback(inner, 9)
    assert inner["field18"] == 50


def test_second_call_is_noop():
    inner = {"first": "obj", "field20": 0, "field18": 100}
    holder = make_holder(flag10=0, inner=inner, cb_arg=30)
    lazy_init(holder)
    lazy_init(holder)
    assert inner["field18"] == 70
    assert holder["flag10"] == 1


def test_flag_range_guard():
    for bad in (-1, 256):
        holder = make_holder(flag10=bad)
        try:
            lazy_init(holder)
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
        ["lazy_init", "callback"]
    assert len(records["caller_records"]) == 2
    for name in ("function_0x605e860.txt", "function_0x606a110.txt",
                 "frames.txt", "relocations.txt", "verify.py",
                 "census.py", "export_excerpts.py", "MANIFEST.sha256",
                 "README.md"):
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
