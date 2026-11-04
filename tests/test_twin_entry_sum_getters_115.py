"""Tests for node #115 twin entry-sum getters 0x5eec290 / 0x5eec300 + leaf 0x5dd3570.

Run under pytest when available, or directly: python3 tests/test_twin_entry_sum_getters_115.py
(pytest is not installed on this VM, so the __main__ runner below is the honest path.)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from twin_entry_sum_getters_115 import getter_a, getter_b, leaf_value, run_getter

M64 = (1 << 64) - 1


def outer(entries):
    return {"member788": {"sub30": {"entries": entries}}}


def test_leaf_adds_62():
    assert leaf_value(0) == 62
    assert leaf_value(100) == 162
    assert leaf_value(M64) == 61  # wraps


def test_a_empty_range_is_zero():
    assert run_getter(getter_a, outer([])) == (1, 0)


def test_b_empty_range_is_zero():
    assert run_getter(getter_b, outer([])) == (1, 0)


def test_a_single_entry():
    assert getter_a([{"f10": 10, "e50": 999}]) == 72


def test_a_multiple_entries():
    entries = [{"f10": 0, "e50": 0}, {"f10": 38, "e50": 0}, {"f10": 1000, "e50": 0}]
    assert getter_a(entries) == 62 + 100 + 1062


def test_a_wraps_64bit():
    assert getter_a([{"f10": M64, "e50": 0}, {"f10": 1, "e50": 0}]) == (61 + 63) & M64


def test_b_sums_e50_not_leaf():
    entries = [{"f10": 0, "e50": 5}, {"f10": 777, "e50": 7}]
    assert getter_b(entries) == 12


def test_b_ignores_leaf_field_entirely():
    # The quirk pinned by this item: B's result is unchanged when f10 varies.
    base = [{"f10": 0, "e50": 40}, {"f10": 0, "e50": 2}]
    wild = [{"f10": M64, "e50": 40}, {"f10": 123456, "e50": 2}]
    assert getter_b(base) == getter_b(wild) == 42


def test_b_wraps_64bit():
    assert getter_b([{"f10": 0, "e50": M64}, {"f10": 0, "e50": 2}]) == 1


def test_both_return_one_and_write_total():
    assert run_getter(getter_a, outer([{"f10": 8, "e50": 3}])) == (1, 70)
    assert run_getter(getter_b, outer([{"f10": 8, "e50": 3}])) == (1, 3)


def test_missing_fields_raise():
    # Getter A reads only f10; getter B reads f10 (call) and e50 (sum).
    for bad in ({}, {"e50": 1}):
        try:
            getter_a([bad])
        except KeyError:
            pass
        else:
            raise AssertionError("getter_a should raise KeyError")
    for bad in ({}, {"f10": 1}, {"e50": 1}):
        try:
            getter_b([bad])
        except KeyError:
            pass
        else:
            raise AssertionError("getter_b should raise KeyError")
    try:
        run_getter(getter_a, {})
    except KeyError:
        pass
    else:
        raise AssertionError("missing member should raise KeyError")


def test_packet_records_exist():
    packet = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-twin-entry-sum-getters-115"
    for name in ("records.json", "MANIFEST.sha256", "verify.py", "export_excerpts.py", "census.py"):
        assert (packet / name).is_file(), f"missing packet file {name}"
    for name in ("getter_a_0x5eec290.objdump", "getter_b_0x5eec300.objdump", "leaf_0x5dd3570.objdump"):
        assert (packet / name).is_file(), f"missing excerpt {name}"


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    for name, fn in tests:
        fn()
        print(f"PASS {name}")
    print(f"{len(tests)} tests passed")
