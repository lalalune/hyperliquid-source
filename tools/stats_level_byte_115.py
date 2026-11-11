"""Model of node #115 StatisticsImpl stats_level_ (RE-001).

The level byte at StatisticsImpl+0x20 is std::atomic<StatsLevel>
(v8.1.1 statistics.h): the ctor writes the header default
kExceptDetailedTimers (3); set_stats_level/get_stats_level are
non-virtual inlines, so the byte has no vtable slot and no other
writer exists in this binary (see the packet census). Nine sites in
eight FDEs read the byte as a gate. This module models the enum, the
four gate shapes and the three instrumented timed-lock helpers, all
against the pinned binary evidence.
"""

# --- StatsLevel (v8.1.1 statistics.h L1079-1117) -------------------------
K_DISABLE_ALL = 0
K_EXCEPT_HISTOGRAM_OR_TIMERS = 1
K_EXCEPT_TIMERS = 2
K_EXCEPT_DETAILED_TIMERS = 3
K_EXCEPT_TIME_FOR_MUTEX = 4
K_ALL = 5

STATS_LEVEL_NAMES = {
    0: "kDisableAll",
    1: "kExceptHistogramOrTimers",
    2: "kExceptTimers",
    3: "kExceptDetailedTimers",
    4: "kExceptTimeForMutex",
    5: "kAll",
}

LEVEL_DEFAULT = K_EXCEPT_DETAILED_TIMERS  # the ctor writes 3
LEVEL_MAX = K_ALL

# --- Pinned binary constants --------------------------------------------
LEVEL_OFFSET = 0x20
CTOR_WRITE_SITE = 0x6071A32
CTOR_WRITE_VALUE = 3
CTOR_FDE = (0x6071A00, 0x6071B60)
STATISTICS_VTABLE = 0x64D2D88
DB_MUTEX_WAIT_MICROS = 52  # Tickers enum order, statistics.h L55-602
TICKER_ID_MAX = 0xB1       # recordTick bound
HIST_ID_MAX = 0x33         # recordHistogram delegate-forward bound

MARKED_FDES = 62
LEVEL_WRITES = 1
LEVEL_READS = 9
MOVB_STORES_BINARY_WIDE = 16889
MOVZBL_LOADS_BINARY_WIDE = 11335
TIMER_CALLS = {"mutex-lock": 244, "condvar-wait": 27,
               "condvar-timedwait": 3, "tls-init": 500,
               "thunk-lock": 2, "thunk-condwait": 2, "thunk-time-math": 1}

# Gate compare immediates, as pinned in the excerpts.
GATE_TICK_LEVEL = 0        # recordTick: level != 0
GATE_HIST_LEVEL = 1        # recordHistogram: level > 1
GATE_FORWARD_LEVEL = 2     # forwarder slot 0xc8: level > 2
GATE_TIMED_LEVEL = 4       # timed-lock helpers: level > 4 (kAll)
GATE_TIMED_CODE = 0x34     # timed path only when code == 52


def level_name(level):
    return STATS_LEVEL_NAMES[level]


def record_tick_allowed(level, ticker_id):
    """recordTick slot 0xb0 (0x606fba0): level != 0 and id <= 0xb1."""
    return level != 0 and 0 <= ticker_id <= TICKER_ID_MAX


def record_hist_allowed(level):
    """recordHistogram slots 0xd8/0xd0: level > 1."""
    return level > GATE_HIST_LEVEL


def forwarder_allowed(level):
    """recordInHistogram slot 0xc8 (0x5d48960): level > 2, else return."""
    return level > GATE_FORWARD_LEVEL


def timed_lock_allowed(stats_present, clock_present, level, code):
    """The three timed helpers (0x606ca40/0x606ccb0/0x606cf20).

    stats_ and clock_ must be non-null, the level must be kAll
    (level > 4) and the stats code must be DB_MUTEX_WAIT_MICROS (52).
    """
    return (stats_present and clock_present
            and level > GATE_TIMED_LEVEL and code == GATE_TIMED_CODE)


class Statistics:
    """A StatisticsImpl as far as the level byte is concerned."""

    def __init__(self, delegate=None):
        # The ctor (0x6071a00) installs the vtable, writes the level
        # byte to the header default and moves in the delegate pair
        # (both factories pass a zeroed args struct: null delegate).
        self.level = LEVEL_DEFAULT
        self.delegate = delegate
        self.ticks = {}   # ticker id -> accumulated count
        self.hists = {}   # hist id -> list of values

    def set_stats_level(self, level):
        # Non-virtual inline: relaxed atomic store == plain byte store.
        if level not in STATS_LEVEL_NAMES:
            raise ValueError("not a StatsLevel: %r" % (level,))
        self.level = level

    def get_stats_level(self):
        # Non-virtual inline: relaxed atomic load == plain byte load.
        return self.level

    def record_tick(self, ticker_id, count=1):
        if not record_tick_allowed(self.level, ticker_id):
            return False
        self.ticks[ticker_id] = self.ticks.get(ticker_id, 0) + count
        if self.delegate is not None:
            self.delegate.record_tick(ticker_id, count)
        return True

    def record_hist(self, hist_id, value):
        if not record_hist_allowed(self.level):
            return False
        self.hists.setdefault(hist_id, []).append(value)
        if self.delegate is not None and hist_id <= HIST_ID_MAX:
            self.delegate.record_hist(hist_id, value)
        return True

    def record_in_histogram(self, hist_id, value):
        # Slot 0xc8 forwarder (0x5d48960): level > 2, else nothing.
        if not forwarder_allowed(self.level):
            return False
        return self.record_hist(hist_id, value)


class FakeClock:
    """The default PosixClock behind the 0x5fe2680 accessor."""

    def __init__(self):
        self.now = 0

    def now_micros(self):
        return self.now

    def advance(self, micros):
        self.now += micros


class InstrumentedMutex:
    """rocksdb::InstrumentedMutex (0x606ca40), modelled on the binary.

    Layout: mutex (40 B, +0x00), stats_ (+0x28), clock_ (+0x30),
    stats_code_ (+0x38). Lock() times the wait only when the stats
    code is DB_MUTEX_WAIT_MICROS and the level is kAll.
    """

    def __init__(self, stats=None, clock=None, code=0):
        self.stats = stats
        self.clock = clock
        self.code = code
        self.locked = False
        self.wait_micros = 0  # time spent blocked in Lock()

    def lock(self, wait_micros=0):
        if timed_lock_allowed(self.stats is not None,
                              self.clock is not None,
                              self.stats.level if self.stats else 0,
                              self.code):
            start = self.clock.now_micros()
            self.clock.advance(wait_micros)
            end = self.clock.now_micros()
            elapsed = end - start
            self.wait_micros += elapsed
            self.stats.record_tick(self.code, elapsed)
            self.locked = True
            return ("timed", elapsed)
        self.locked = True
        return ("plain", 0)

    def unlock(self):
        self.locked = False


class InstrumentedCondVar:
    """rocksdb::InstrumentedCondVar (0x606ccb0 Wait, 0x606cf20 TimedWait).

    Layout: cond_ (56 B: 48-B pthread_cond_t + the mutex pointer),
    stats_ (+0x38), clock_ (+0x40), stats_code_ (+0x48).
    """

    def __init__(self, stats=None, clock=None, code=0):
        self.stats = stats
        self.clock = clock
        self.code = code

    def wait(self, wait_micros=0):
        if timed_lock_allowed(self.stats is not None,
                              self.clock is not None,
                              self.stats.level if self.stats else 0,
                              self.code):
            start = self.clock.now_micros()
            self.clock.advance(wait_micros)
            elapsed = self.clock.now_micros() - start
            self.stats.record_tick(self.code, elapsed)
            return ("timed", elapsed)
        return ("plain", 0)

    def timed_wait(self, abs_time_us, wait_micros=0):
        # The timeout is split by the 0x606cee0 thunk (see
        # split_microseconds); the report is the same as Wait.
        _sec, _rem = split_microseconds(abs_time_us)
        return self.wait(wait_micros)


def split_microseconds(value_us):
    """The 0x60d55f0 time math: value / 1,000,000 and value % 1,000,000.

    The binary does it with the magic 0x431bde82d7b634db; the model
    uses plain division, which the tests cross-check against the
    magic-number computation on seeded inputs.
    """
    return (value_us // 1000000, value_us % 1000000)


def split_microseconds_magic(value_us):
    """The binary's own method: multiply by the magic, shift, subtract."""
    magic = 0x431BDE82D7B634DB
    q = ((value_us * magic) & ((1 << 128) - 1)) >> 64
    q >>= 0x12
    return (q, value_us - q * 1000000)


class TlsOnce:
    """The 0x606dd10 TLS once-init: first call initializes, later calls
    are no-ops (the byte at %fs:-0x358)."""

    def __init__(self):
        self.initialized = False
        self.calls = 0

    def ensure(self):
        self.calls += 1
        if self.initialized:
            return False
        self.initialized = True
        return True


def build_statistics(delegate=None):
    """Either factory (0x6071ba0 / 0x6077820): new(0x70) + the ctor
    with a zeroed delegate-args struct."""
    return Statistics(delegate=delegate)
