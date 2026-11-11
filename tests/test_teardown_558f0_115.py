"""Tests for the node #115 guarded teardown model 0x5d558f0.

Run directly (pytest is not installed on this VM):
    python3 -c "import tests.test_teardown_558f0_115 as t; ..."
or via the packet verify.py, which runs every test_* function here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from teardown_558f0_115 import teardown


def test_all_null_still_destroys_condvar():
    # The +0x40 destroy is unconditional: even a fully null object
    # reaches the wrapper.
    assert teardown(None, None, 0, None, None, None) == [
        ("cond_destroy", 0),
    ]


def test_full_order():
    assert teardown("r", 0, 0, "a38", "a28", "a18") == [
        ("release", "r"),
        ("sized_delete", "cell98", 8),
        ("cond_destroy", 0),
        ("delete_array", "38"),
        ("delete_array", "28"),
        ("delete_array", "18"),
    ]


def test_null_ref_skips_release_only():
    assert teardown(None, 0, 16, "a38", None, None) == [
        ("sized_delete", "cell98", 8),
        ("cond_destroy", 16),
        ("delete_array", "38"),
    ]


def test_null_cell_skips_cell_only():
    assert teardown("r", None, 110, None, "a28", None) == [
        ("release", "r"),
        ("cond_destroy", 110),
        ("delete_array", "28"),
    ]


def test_nonzero_cell_terminates_and_stops():
    # A nonzero first qword ends the process: no condvar destroy and
    # no array frees run after it.
    assert teardown("r", 7, 0, "a38", "a28", "a18") == [
        ("release", "r"),
        ("terminate",),
    ]


def test_condvar_tolerated_codes():
    for code in (0, 16, 110):
        assert teardown(None, None, code, None, None, "a18") == [
            ("cond_destroy", code),
            ("delete_array", "18"),
        ]


def test_condvar_other_code_aborts_and_stops():
    assert teardown("r", 0, 22, "a38", "a28", "a18") == [
        ("release", "r"),
        ("sized_delete", "cell98", 8),
        ("cond_destroy_abort", 22),
    ]


def test_null_arrays_skip_individually():
    assert teardown(None, None, 0, None, "a28", None) == [
        ("cond_destroy", 0),
        ("delete_array", "28"),
    ]


def test_tail_array_present():
    assert teardown(None, None, 0, None, None, "a18") == [
        ("cond_destroy", 0),
        ("delete_array", "18"),
    ]
