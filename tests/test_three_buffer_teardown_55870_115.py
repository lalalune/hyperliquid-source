"""Tests for the node #115 three-buffer teardown model 0x5d55870.

Run directly (pytest is not installed on this VM):
    python3 -c "import tests.test_three_buffer_teardown_55870_115 as t; ..."
or via the packet verify.py, which runs every test_* function here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from three_buffer_teardown_55870_115 import teardown


def test_all_null_no_frees():
    assert teardown((None, 0), (None, 0), (None, 0), None) == []


def test_full_order_a_b_c_then_release():
    assert teardown((100, 140), (200, 215), (300, 300 + 64), "r") == [
        ("sized_delete", "A", 100, 40),
        ("sized_delete", "B", 200, 15),
        ("sized_delete", "C", 300, 64),
        ("release", "r"),
    ]


def test_null_buffer_skips_only_itself():
    assert teardown((None, 0), (200, 210), (None, 0), "r") == [
        ("sized_delete", "B", 200, 10),
        ("release", "r"),
    ]


def test_empty_nonnull_buffer_still_frees_size_zero():
    assert teardown((100, 100), (None, 0), (None, 0), None) == [
        ("sized_delete", "A", 100, 0),
    ]


def test_null_ref_skips_release_only():
    assert teardown((100, 105), (None, 0), (None, 0), None) == [
        ("sized_delete", "A", 100, 5),
    ]


def test_size_is_end_minus_begin_not_capacity():
    # A buffer whose end is below begin in the model input is not a
    # target-grounded shape; the honest check is arithmetic only:
    assert teardown((1000, 1000 + 7), (None, 0), (None, 0), None) == [
        ("sized_delete", "A", 1000, 7),
    ]
