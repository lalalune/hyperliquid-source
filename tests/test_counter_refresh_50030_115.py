"""Tests for the node #115 routine 0x5d50030 model (RE-001 counter refresh).

Run directly (pytest is not installed on this VM):
    python3 -c "import importlib.util; ..."
or through the packet's verify.py, which runs every test_* function here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from counter_refresh_50030_115 import (  # noqa: E402
    KNOWN_HANDLER, KNOWN_PRODUCER, refresh)

OTHER_PRODUCER = 0x5D40000
OTHER_HANDLER = 0x5D40010


def test_accumulate_adds_producer_minus_sub38():
    counter, exit_, ops = refresh(10, 0, 0, 0, 3, 7, 5,
                                  slot98=OTHER_PRODUCER)
    assert (counter, exit_) == (12, "return")
    assert ops == [("producer", "direct"), ("store", 12)]


def test_replace_stores_producer_minus_sub38():
    counter, exit_, ops = refresh(10, 1, 0, 0, 3, 7, 5,
                                  slot98=OTHER_PRODUCER)
    assert (counter, exit_) == (2, "return")
    assert ops == [("producer", "direct"), ("store", 2)]


def test_extra_subtract_applies_second_store():
    counter, exit_, ops = refresh(10, 0, 0, 1, 3, 7, 5,
                                  slot98=OTHER_PRODUCER)
    assert (counter, exit_) == (5, "return")
    assert ops == [("producer", "direct"), ("store", 5)]


def test_known_producer_uses_delegate_label():
    _, _, ops = refresh(0, 0, 0, 0, 0, 0, 9, slot98=KNOWN_PRODUCER)
    assert ops[0] == ("producer", "delegate")


def test_phase_b_skipped_when_flag21_zero():
    counter, exit_, ops = refresh(4, 0, 0, 0, 1, 0, 2,
                                  slot98=OTHER_PRODUCER,
                                  slot_c8=OTHER_HANDLER, waiter_byte=9)
    assert (counter, exit_) == (5, "return")
    assert ops == [("producer", "direct"), ("store", 5)]


def test_null_counter_and_flag21_zero_returns_at_once():
    counter, exit_, ops = refresh(None, 0, 0, 0, 3, 0, 8)
    assert (counter, exit_, ops) == (None, "return", [])


def test_null_counter_phase_b_direct_handler_call():
    counter, exit_, ops = refresh(None, 0, 1, 0, 3, 0, 8,
                                  slot_c8=OTHER_HANDLER, waiter_byte=9)
    assert counter is None
    assert exit_ == "handler_call"
    assert ops == [("producer_null_path", 5, "computed_unconsumed"),
                   ("handler", "direct_call")]


def test_known_handler_low_waiter_byte_returns():
    counter, exit_, ops = refresh(4, 0, 1, 0, 1, 0, 2,
                                  slot98=OTHER_PRODUCER,
                                  slot_c8=KNOWN_HANDLER, waiter_byte=2)
    assert (counter, exit_) == (5, "return")
    assert ops == [("producer", "direct"), ("store", 5)]


def test_known_handler_high_waiter_byte_tail_dispatches():
    counter, exit_, ops = refresh(4, 0, 1, 0, 1, 0, 2,
                                  slot98=OTHER_PRODUCER,
                                  slot_c8=KNOWN_HANDLER, waiter_byte=3)
    assert (counter, exit_) == (5, "tail_dispatch")
    assert ops == [("producer", "direct"), ("store", 5),
                   ("handler", "tail_dispatch")]


def test_full_path_accumulate_extra_subtract_tail_dispatch():
    counter, exit_, ops = refresh(100, 0, 1, 1, 10, 4, 20,
                                  slot98=KNOWN_PRODUCER,
                                  slot_c8=KNOWN_HANDLER, waiter_byte=9)
    assert (counter, exit_) == (106, "tail_dispatch")
    assert ops == [("producer", "delegate"), ("store", 106),
                   ("handler", "tail_dispatch")]


def test_counter_arithmetic_wraps_64_bit():
    counter, exit_, ops = refresh(0, 0, 0, 0, 1, 0, 0,
                                  slot98=OTHER_PRODUCER)
    assert counter == (1 << 64) - 1
    assert exit_ == "return"
