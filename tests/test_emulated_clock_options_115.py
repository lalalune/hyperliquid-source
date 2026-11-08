"""Tests for the EmulatedSystemClock options model.

Grounded in research/work-items/RE-001-emulated-clock-options-115/:
the bool parser accepts exactly "true"/"1"/"false"/"0"; the
time_elapse_only_sleep setter writes both flags; the mock_sleep setter
writes only +0x49; SleepForMicroseconds advances the +0x40 offset when
either flag is set and skips the real sleep only when mock_sleep is
set; GetCurrentTime returns the stored +0x30 time while emulating.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import pytest
from emulated_clock_options_115 import (
    EmulatedClockOptions, format_bool, parse_bool,
)


class FakeClock:
    """Stand-in for the wrapped SystemClock."""

    def __init__(self, micros=1_000_000, nanos=1_000_000_000,
                 current_time=1_337_038_800):
        self.micros = micros
        self.nanos = nanos
        self.current_time = current_time
        self.slept = []

    def now_micros(self):
        return self.micros

    def now_nanos(self):
        return self.nanos

    def sleep_for_microseconds(self, duration_us):
        self.slept.append(duration_us)

    def get_current_time(self):
        return self.current_time


def test_parse_bool_accepted_spellings():
    assert parse_bool("true") is True
    assert parse_bool("1") is True
    assert parse_bool("false") is False
    assert parse_bool("0") is False


def test_parse_bool_rejects_other_spellings():
    for bad in ("yes", "True", "TRUE", "2", "", " true", "tru"):
        with pytest.raises(ValueError):
            parse_bool(bad)


def test_getters_format_flags():
    opts = EmulatedClockOptions(FakeClock(), time_elapse_only_sleep=True)
    assert opts.get_option("time_elapse_only_sleep") == "true"
    assert opts.get_option("mock_sleep") == "false"
    assert format_bool(False) == "false"


def test_unknown_option_raises():
    opts = EmulatedClockOptions(FakeClock())
    with pytest.raises(KeyError):
        opts.get_option("supports_direct_io")
    with pytest.raises(KeyError):
        opts.set_option("supports_direct_io", "true")


def test_time_elapse_setter_writes_both_flags():
    opts = EmulatedClockOptions(FakeClock())
    opts.set_option("time_elapse_only_sleep", "true")
    assert opts.time_elapse_only_sleep is True
    assert opts.mock_sleep is True
    opts.set_option("time_elapse_only_sleep", "0")
    assert opts.time_elapse_only_sleep is False
    assert opts.mock_sleep is False


def test_mock_sleep_setter_writes_only_mock():
    opts = EmulatedClockOptions(FakeClock(), time_elapse_only_sleep=True)
    opts.set_option("mock_sleep", "false")
    assert opts.mock_sleep is False
    assert opts.time_elapse_only_sleep is True


def test_sleep_neither_flag_delegates_without_offset():
    wrapped = FakeClock()
    opts = EmulatedClockOptions(wrapped)
    opts.sleep_for_microseconds(500)
    assert opts.offset_us == 0
    assert opts.sleep_count == 1
    assert wrapped.slept == [500]
    assert opts.real_sleeps == [500]


def test_sleep_mock_advances_offset_and_skips_real_sleep():
    wrapped = FakeClock()
    opts = EmulatedClockOptions(wrapped, mock_sleep=True)
    opts.sleep_for_microseconds(700)
    assert opts.offset_us == 700
    assert wrapped.slept == []
    assert opts.real_sleeps == []


def test_sleep_time_elapse_advances_offset_and_still_sleeps():
    wrapped = FakeClock()
    opts = EmulatedClockOptions(wrapped, time_elapse_only_sleep=True)
    opts.sleep_for_microseconds(300)
    assert opts.offset_us == 300
    assert wrapped.slept == [300]
    assert opts.real_sleeps == [300]


def test_get_current_time_emulated_vs_delegated():
    wrapped = FakeClock(current_time=9_999)
    opts = EmulatedClockOptions(wrapped, stored_time=1_337_038_800,
                                time_elapse_only_sleep=True)
    assert opts.get_current_time() == 1_337_038_800
    opts.set_option("time_elapse_only_sleep", "false")
    # Unsetting time_elapse also clears mock_sleep (setter writes both).
    assert opts.get_current_time() == 9_999


def test_now_micros_nanos_use_offset():
    wrapped = FakeClock(micros=1_000_000, nanos=1_000_000_000)
    opts = EmulatedClockOptions(wrapped, mock_sleep=True)
    opts.sleep_for_microseconds(250)
    assert opts.now_micros() == 1_000_250
    assert opts.now_nanos() == 1_000_250_000
    opts.set_option("time_elapse_only_sleep", "true")
    assert opts.now_micros() == 250
    assert opts.now_nanos() == 250_000
