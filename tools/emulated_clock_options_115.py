"""Model of node #115's EmulatedSystemClock options and time methods.

Evidence: research/work-items/RE-001-emulated-clock-options-115/.

The two option maps (0x6505960 "time_elapse_only_sleep", 0x6505920
"mock_sleep") hold one bool each, at object+0x48 and object+0x49.
The getters format the flag as "true"/"false"; the setters parse with
the bool parser 0x61d1480. Setting "time_elapse_only_sleep" writes
BOTH flags; setting "mock_sleep" writes only +0x49. SleepForMicroseconds
(slot 23) advances the emulated-time offset at +0x40 (microseconds)
when either flag is set, and performs the real sleep unless mock_sleep
is set. GetCurrentTime (slot 24) returns the stored time at +0x30
while time_elapse_only_sleep is set, else delegates to the wrapped
clock. NowMicros/NowNanos return the wrapped clock's value plus the
+0x40 offset (x1000 for nanos) when the flag is clear, else just the
offset. GetCurrentTime returns the stored +0x30 time (emulating) or
the wrapped clock's value (delegating), plus the +0x40 offset
converted from microseconds to whole seconds (division by 1,000,000)
when the Status is kOk -- the binary's 0x6025f92..0x6025fae tail
(magic-multiply idiom) applies to both paths.
"""


def parse_bool(text):
    """Mirror of the bool parser 0x61d1480.

    Accepts exactly "true"/"1" (True) and "false"/"0" (False). Any
    other spelling throws in the binary (shared throw block at
    0x61d1437); here it raises ValueError.
    """
    if text in ("true", "1"):
        return True
    if text in ("false", "0"):
        return False
    raise ValueError(f"not a bool spelling: {text!r}")


def format_bool(flag):
    """Mirror of the bool getters 0x6025e50 / 0x6026100."""
    return "true" if flag else "false"


def _div_1e6(value):
    """Signed division by 1,000,000 truncating toward zero.

    Mirrors the magic-multiply idiom at 0x6025f92..0x6025fab
    (magic 0x431bde82d7b634db, sar 0x12, sign correction).
    """
    q = abs(value) // 1_000_000
    return -q if value < 0 else q


class EmulatedClockOptions:
    """The EmulatedSystemClock's two options plus its time state.

    ``wrapped`` is the wrapped clock: an object with ``now_micros()``,
    ``now_nanos()``, ``sleep_for_microseconds(us)`` and
    ``get_current_time()``. ``stored_time`` is the +0x30 value the
    ctor seeds from the wrapped clock's GetCurrentTime.
    """

    def __init__(self, wrapped, stored_time=0x4FB647D0,
                 time_elapse_only_sleep=False, mock_sleep=False):
        self.wrapped = wrapped
        self.stored_time = stored_time
        self.time_elapse_only_sleep = bool(time_elapse_only_sleep)
        self.mock_sleep = bool(mock_sleep)
        self.offset_us = 0          # object+0x40, microseconds
        self.sleep_count = 0        # object+0x38
        self.real_sleeps = []       # durations actually slept (for tests)

    def get_option(self, name):
        if name == "time_elapse_only_sleep":
            return format_bool(self.time_elapse_only_sleep)
        if name == "mock_sleep":
            return format_bool(self.mock_sleep)
        raise KeyError(name)

    def set_option(self, name, value):
        parsed = parse_bool(value)
        if name == "time_elapse_only_sleep":
            # Setter 0x6026ba0 writes BOTH +0x48 and +0x49.
            self.time_elapse_only_sleep = parsed
            self.mock_sleep = parsed
        elif name == "mock_sleep":
            # Setter 0x6026ad0 writes +0x49 only.
            self.mock_sleep = parsed
        else:
            raise KeyError(name)

    def sleep_for_microseconds(self, duration_us):
        """Mirror of slot 23 (0x6025b40)."""
        self.sleep_count += 1
        if self.mock_sleep or self.time_elapse_only_sleep:
            self.offset_us += duration_us
        if not self.mock_sleep:
            self.wrapped.sleep_for_microseconds(duration_us)
            self.real_sleeps.append(duration_us)

    def get_current_time(self):
        """Mirror of slot 24 (0x6025eb0).

        Base value: the stored +0x30 time while emulating, else the
        wrapped clock's value. Both paths then add the +0x40 offset
        converted from microseconds to whole seconds (signed division
        by 1,000,000, truncating toward zero) when the Status is kOk
        -- the binary skips the add on an error Status (jne 0x6025f03).
        The model assumes kOk throughout (the wrapped clock never
        fails here).
        """
        if self.time_elapse_only_sleep:
            base = self.stored_time
        else:
            base = self.wrapped.get_current_time()
        return base + _div_1e6(self.offset_us)

    def now_micros(self):
        """Mirror of slot 19 (0x60259e0)."""
        base = 0 if self.time_elapse_only_sleep else self.wrapped.now_micros()
        return base + self.offset_us

    def now_nanos(self):
        """Mirror of slot 20 (0x60259a0)."""
        base = 0 if self.time_elapse_only_sleep else self.wrapped.now_nanos()
        return base + self.offset_us * 1000
