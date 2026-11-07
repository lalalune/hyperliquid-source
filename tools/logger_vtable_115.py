"""Model of node #115's Logger and AutoRollLogger vtable maps (RE-001).

Pure-Python model of the behaviors pinned by the evidence packet
research/work-items/RE-001-logger-vtable-full-map-115/ for
lalalune/hyperliquid-source node #115 (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The model covers the complete Logger + AutoRollLogger vtable maps
(11 slots each), the level gates, the log-write path (timestamp
format, dirty flag, cached-size refresh), the rollover triggers, the
header queue, the writer error contract, and the object layouts --
each rule traced to a function body in the packet's verbatim excerpts.
"""

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)

# InfoLogLevel (env.h): 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR, 4=FATAL,
# 5=HEADER.
DEBUG_LEVEL = 0
INFO_LEVEL = 1
WARN_LEVEL = 2
ERROR_LEVEL = 3
FATAL_LEVEL = 4
HEADER_LEVEL = 5

# PerfLevel: 0=kDisable, 1=kEnableCount, 2=kEnableTimeExceptForMutex,
# 3=kEnableTime, 4=kEnableTimeAndCPUTime.  Timing is active iff > 2.
PERF_DISABLE = 0
PERF_ENABLE_COUNT = 1
PERF_ENABLE_TIME_EXCEPT_MUTEX = 2
PERF_ENABLE_TIME = 3
PERF_ENABLE_TIME_AND_CPU = 4

# EnvLogger Logv (0x5fce280): refresh the cached file size at +0x130
# iff (size - last) exceeds this threshold.
SIZE_REFRESH_THRESHOLD = 0x4C4B3F  # 4,999,999

# The timestamp format string at 0x968038 (verbatim C format).
TIMESTAMP_FORMAT = "%04d/%02d/%02d-%02d:%02d:%02d.%06d %llu "
# The same format expressed for Python's % operator (%llu -> %d).
_PY_TIMESTAMP_FORMAT = "%04d/%02d/%02d-%02d:%02d:%02d.%06d %d "

# Writer error message, assembled from the two 16-byte chunks at
# 0x451480 ("Writer has previ") and 0x452bf0 (" previous error.").
WRITER_PREVIOUS_ERROR = "Writer has previous error."

# CloseImpl worker error prefix (0x966d00, 36 chars).
CLOSE_ERROR_PREFIX = "Close of log file failed with error:"

# IOStatus code for the writer/close errors.
K_IO_ERROR = 5

# The AutoRollLogger roll function (0x6058110) and its callees.
AUTOROLL_ROLL_FN = 0x6058110
AUTOROLL_TIMECHECK_FN = 0x6057310
AUTOROLL_RELOG_FN = 0x60572A0

# Object sizes: EnvLogger 0x140 (inside a 0x150-byte
# _Sp_counted_ptr_inplace<EnvLogger> control block); AutoRollLogger
# 0x290 (operator delete of 0x290 in D1).
ENVLOGGER_SIZE = 0x140
ENVLOGGER_CONTROL_BLOCK_SIZE = 0x150
AUTOROLL_SIZE = 0x290

# EnvLogger vtable 0x64cda68 / AutoRollLogger vtable 0x64d1f00.
ENVLOGGER_VTABLE = 0x64CDA68
AUTOROLL_VTABLE = 0x64D1F00

ENVLOGGER_SLOTS = {
    0: (0x5FCFB90, "~EnvLogger (D0)"),
    1: (0x5FCFDE0, "~EnvLogger (D1)"),
    2: (0x5FCC410, "Close()"),
    3: (0x5FCC200, "LogHeader(const char*, va_list)"),
    4: (0x5FCE280, "Logv(const char*, va_list)"),
    5: (0x5FCD400, "Logv(InfoLogLevel, const char*, va_list)"),
    6: (0x5FCCED0, "GetLogFileSize() const"),
    7: (0x5FCE130, "Flush()"),
    8: (0x5FCC220, "GetInfoLogLevel() const"),
    9: (0x5FCC230, "SetInfoLogLevel(InfoLogLevel)"),
    10: (0x5FCEAE0, "CloseImpl()"),
}

AUTOROLL_SLOTS = {
    0: (0x60576B0, "~AutoRollLogger (D0)"),
    1: (0x6057D00, "~AutoRollLogger (D1)"),
    2: (0x5FCC410, "Close()"),  # shared with EnvLogger
    3: (0x6057000, "LogHeader(const char*, va_list)"),
    4: (0x6058770, "Logv(const char*, va_list)"),
    5: (0x5FCD400, "Logv(InfoLogLevel, const char*, va_list)"),  # shared
    6: (0x6057590, "GetLogFileSize() const"),
    7: (0x6057440, "Flush()"),
    8: (0x60552E0, "GetInfoLogLevel() const"),
    9: (0x6055280, "SetInfoLogLevel(InfoLogLevel)"),
    10: (0x60551D0, "CloseImpl()"),
}

# Shared slots between the two vtables (same function address).
SHARED_SLOTS = (2, 5)

# EnvLogger layout offsets (see the packet README for the field table).
ENVLOGGER_OFF = {
    "vtable": 0x00,
    "closed_": 0x10,
    "log_level_": 0x11,
    "env": 0x18,
    "file": 0x20,
    "writer": 0x28,
    "fname": 0x28,
    "cached_size": 0x98,
    "mutex": 0x108,
    "last_size": 0x130,
    "dirty": 0x138,
}

# AutoRollLogger layout offsets.
AUTOROLL_OFF = {
    "vtable": 0x00,
    "closed_": 0x10,
    "log_level_": 0x11,
    "fname_a": 0x38,
    "fname_b": 0x58,
    "fname_c": 0x78,
    "shared_a": 0x98,
    "shared_b": 0xA8,
    "logger_": 0xB8,
    "log_max_size": 0xD8,
    "time_to_roll": 0xE0,
    "headers": 0xF0,
    "header_count": 0x100,
    "mutex": 0x268,
}


def level_gate(log_level, level):
    """The slot-5 gate (0x5fcd400): a message at `level` is written
    iff level >= log_level_ (+0x11); otherwise it is dropped."""
    return level >= log_level


def perf_timing_active(perf_level):
    """Timing is active iff perf_level > 2 (kEnableTime and above)."""
    return perf_level > 2


def timestamp_prefix(year, month, day, hour, minute, second, usec,
                     thread_id):
    """The Logv timestamp line (format string at 0x968038)."""
    return _PY_TIMESTAMP_FORMAT % (year, month, day, hour, minute, second,
                                   usec, thread_id)


def ensure_trailing_newline(line):
    """Logv ensures a trailing newline on the formatted line."""
    return line if line.endswith("\n") else line + "\n"


def size_refresh_needed(size, last_size):
    """EnvLogger Logv refreshes [+0x130] iff (size - [+0x130]) >
    0x4c4b3f.  (size and last_size are u64; the subtraction is the
    unsigned difference as the binary computes it.)"""
    return (size - last_size) & 0xFFFFFFFFFFFFFFFF > SIZE_REFRESH_THRESHOLD


def roll_needed(size, log_max_size, time_check):
    """AutoRollLogger Logv (0x6058770): roll iff the time check says so
    (when +0xe0 != 0) or the size gate fires (+0xd8 != 0 and the wrapped
    size >= +0xd8).  `time_check` is the 0x6057310 result (0 = no roll);
    pass False when +0xe0 == 0 (no time roll configured)."""
    if time_check:
        return True
    return log_max_size != 0 and size >= log_max_size


def writer_append(has_previous_error):
    """WritableFileWriter Append (0x6054680): if the writer's previous-
    error flag (+0x89) is set, the append fails with kIOError and the
    'Writer has previous error.' message; otherwise it proceeds."""
    if has_previous_error:
        return (K_IO_ERROR, WRITER_PREVIOUS_ERROR)
    return (0, "")


def close_error_message(writer_error):
    """The CloseImpl worker (0x5fce770) builds kIOError with
    'Close of log file failed with error:' + the writer's error
    string when the writer Close fails."""
    return CLOSE_ERROR_PREFIX + writer_error


def close_impl(closed):
    """EnvLogger Close (0x5fcc410) is idempotent: when closed_ is set
    it returns OK without calling CloseImpl; otherwise CloseImpl runs.
    `closed` is the current closed_ flag; returns
    (close_impl_called, closed_after)."""
    if closed:
        return (False, True)
    return (True, True)  # CloseImpl runs; closed_ becomes set


def autoroll_get_log_level(wrapped_level, own_level):
    """AutoRollLogger slot 8 (0x60552e0): when a wrapped logger is
    present its level is returned, else the own +0x11."""
    return wrapped_level if wrapped_level is not None else own_level


def autoroll_set_log_level(wrapped_present):
    """AutoRollLogger slot 9 (0x6055280): always stores the level at
    the own +0x11; additionally forwards it to the wrapped logger's
    slot 9 when present.  Returns whether the wrapped logger is
    updated."""
    return wrapped_present


def autoroll_close_impl(wrapped_present):
    """AutoRollLogger slot 10 (0x60551d0): when no wrapped logger is
    present the status is OK; otherwise the wrapped logger's Close
    (slot 2, NOT CloseImpl) produces the status."""
    return "OK" if not wrapped_present else "delegated to wrapped Close"


def autoroll_get_log_file_size(wrapped_present, wrapped_size):
    """AutoRollLogger slot 6 (0x6057590): null wrapped logger -> 0;
    otherwise the wrapped logger's size."""
    return 0 if not wrapped_present else wrapped_size


def buffer_growth(capacity, needed):
    """The writer Append buffer (std::string at writer+0x50/+0x58/
    +0x68) grows by doubling until it fits `needed` bytes."""
    cap = capacity
    while cap < needed:
        cap *= 2
    return cap


def slot_name(vtable, slot):
    """The C++ name of a Logger vtable slot, or None for an unknown
    slot (slots 11+ are unpinned: see the packet README)."""
    table = (ENVLOGGER_SLOTS if vtable == ENVLOGGER_VTABLE
             else AUTOROLL_SLOTS if vtable == AUTOROLL_VTABLE else None)
    if table is None or slot not in table:
        return None
    return table[slot][1]


def slot_fn(vtable, slot):
    """The function address of a Logger vtable slot, or None."""
    table = (ENVLOGGER_SLOTS if vtable == ENVLOGGER_VTABLE
             else AUTOROLL_SLOTS if vtable == AUTOROLL_VTABLE else None)
    if table is None or slot not in table:
        return None
    return table[slot][0]
