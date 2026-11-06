"""Python model of node #115's compaction-stats per-level data-row formatter.

The formatter is the routine at 0x5eed6f0 (FDE 0x5eed6f0..0x5eedd9e).  It
writes one data row into the caller's character buffer (the big dump
caller's stack buffer at rsp+0x4c0, 2024 bytes) with a single
__snprintf_chk call on a 2000-byte budget:

    %4s %6d/%-3d %8s %5.1f %8.1f %7.1f %8.1f %9.1f %8.1f %9.1f %5.1f %8.1f %8.1f
    %9.2f %17.2f %9d %8.3f %7s %6s %9.1f %9.1f\\n

The 22 fields are the caller-supplied label followed by the 21 metric
values of one per-level (or Sum / Int / priority) map<int, double>,
keys 1..21 in order.  The metric names are the global pair map's FIRST
strings (see research/work-items/RE-001-compaction-stats-header-115/
records.json, pair_table; keys 1..21).  The row's 22 fields sit under
the header's 21 columns: the %6d/%-3d pair (NumFiles/CompactedFiles)
shares the header's single "Files" column, and the other 19 metric
fields sit under the header columns for keys 3..21.  The header row is
192 characters long including the newline; a data row is 192
characters when the human-size string fits in its %8s field, and
longer when it does not (e.g. "117.74 MB" is 9 characters).

How each metric is read and rendered (verified against main.txt):

* keys 21, 20, 19, 18, 16, 14, 13, 10, 9, 7, 6, 5, 4, 3 come from the
  map accessor 0x5eebac0 (std::map<int, double>::at: lower_bound(key) +
  equality check, throws __throw_out_of_range("map::at") on a miss);
  keys 17, 15, 12, 11, 8, 2, 1 come from seven inlined lower_bound +
  equality lookups that throw at the same message (0x4408a7).
* keys 1, 2, 16 are truncated to 32-bit int with cvttsd2si and printed
  %6d, %-3d, %9d.  A missing key throws; a NaN / infinite /
  out-of-range double truncates to INT32_MIN, exactly as cvttsd2si to
  a 32-bit register does.
* key 3 (SizeBytes) is converted to an unsigned long the same way the
  binary does (plain cvttsd2si below 2**63, subtract-2**63 + flip-bit-63
  at or above it) and printed by the human-size formatter 0x61d0ba0:
  "%.2f KB|MB|GB|TB", scaling by 1/1024 until below 1024.0.  A negative
  long is treated as its unsigned bit pattern, as the formatter does.
* keys 18, 19 (KeyIn, KeyDrop) are truncated to long and printed by the
  integer formatter 0x61d0940: "%li" (|n| <= 9999), "%liK" (n/1000,
  |n| <= 9999999), "%liM" (n/1e6, |n| <= 9999999999), "%liG" (n/1e9),
  with truncating signed division.
* the other keys print as doubles: %5.1f (4), %8.1f (5), %7.1f (6),
  %8.1f (7), %9.1f (8), %8.1f (9), %9.1f (10), %5.1f (11), %8.1f (12),
  %8.1f (13), %9.2f (14), %17.2f (15), %8.3f (17), %9.1f (20),
  %9.1f (21).  The 15 doubles reach the snprintf as xmm0..xmm7 (keys
  4..11) plus seven stack varargs (keys 12, 13, 14, 15, 17, 20, 21);
  the full vararg order is re-derived from main.txt by verify.py.

The formatter is called exactly four times, all inside the big dump
caller 0x5ef66e0..0x5ef8049 (see callers.tsv): once per level with the
label "L" + decimal(level) (0x5ef6b84), once for the Sum row with the
label "Sum" (0x5ef6e09), once for the aggregate row with the label
"Int" (0x5ef70de), and once per priority with the label from the
priority-name table (0: Bottom, 1: Low, 2: High, 3: User, else Invalid)
via 0x5fcebc0 (0x5ef72dd).  The caller appends the buffer to its output
string after each call.
"""

import math
import re
import struct

# First strings of the global pair map at 0x6503a00, keys 1..21: the
# metric names.  Derived from the static initializer 0x5efbd80; see
# research/work-items/RE-001-compaction-stats-header-115/records.json
# (pair_table) and derive_names.py there.
FIRST = {
    1: "NumFiles",
    2: "CompactedFiles",
    3: "SizeBytes",
    4: "Score",
    5: "ReadGB",
    6: "RnGB",
    7: "Rnp1GB",
    8: "WriteGB",
    9: "WnewGB",
    10: "MovedGB",
    11: "WriteAmp",
    12: "ReadMBps",
    13: "WriteMBps",
    14: "CompSec",
    15: "CompMergeCPU",
    16: "CompCount",
    17: "AvgSec",
    18: "KeyIn",
    19: "KeyDrop",
    20: "RblobGB",
    21: "WblobGB",
}

# Second strings (the header-row display names) for the same keys.
SECOND = {
    1: "Files",
    2: "CompactedFiles",
    3: "Size",
    4: "Score",
    5: "Read(GB)",
    6: "Rn(GB)",
    7: "Rnp1(GB)",
    8: "Write(GB)",
    9: "Wnew(GB)",
    10: "Moved(GB)",
    11: "W-Amp",
    12: "Rd(MB/s)",
    13: "Wr(MB/s)",
    14: "Comp(sec)",
    15: "CompMergeCPU(sec)",
    16: "Comp(cnt)",
    17: "Avg(sec)",
    18: "KeyIn",
    19: "KeyDrop",
    20: "Rblob(GB)",
    21: "Wblob(GB)",
}

# Row column keys after the label, in the order the formatter passes
# them to the row snprintf (derived from main.txt: the 14 map::at
# calls plus the 7 inlined lookups, then the register/stack varargs
# in format order; see verify.py check 10).
COLUMN_KEYS = list(range(1, 22))

# The row format literal at 0x96c040.
ROW_FORMAT = ("%4s %6d/%-3d %8s %5.1f %8.1f %7.1f %8.1f %9.1f %8.1f %9.1f "
              "%5.1f %8.1f %8.1f %9.2f %17.2f %9d %8.3f %7s %6s %9.1f "
              "%9.1f\n")

# (key, printf width, precision) for the 15 double columns, in format
# order.
DOUBLE_COLUMNS = [
    (4, 5, 1), (5, 8, 1), (6, 7, 1), (7, 8, 1), (8, 9, 1), (9, 8, 1),
    (10, 9, 1), (11, 5, 1), (12, 8, 1), (13, 8, 1), (14, 9, 2),
    (15, 17, 2), (17, 8, 3), (20, 9, 1), (21, 9, 1),
]

MAXLEN = 2000
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


def cvttsd2si(value):
    """Truncate a double to a signed 64-bit long, as cvttsd2si does.

    NaN, infinities and out-of-range values yield INT64_MIN (the
    instruction's indefinite value).
    """
    if math.isnan(value) or math.isinf(value):
        return INT64_MIN
    if value >= 2.0 ** 63 or value < -2.0 ** 63:
        return INT64_MIN
    return int(value)


def cvttsd2si32(value):
    """Truncate a double to a signed 32-bit int, as cvttsd2si to a
    32-bit register does (the form the formatter uses for keys 1, 2
    and 16).  NaN, infinities and out-of-range values yield INT32_MIN.
    """
    if math.isnan(value) or math.isinf(value):
        return -(1 << 31)
    if value >= 2.0 ** 31 or value < -2.0 ** 31:
        return -(1 << 31)
    return int(value)


def trunc_div(n, d):
    """Truncating signed division, as the magic-multiply sequences do."""
    q = abs(n) // d
    return q if n >= 0 else -q


def int_format(n):
    """The integer formatter 0x61d0940: "%li" / "%liK" / "%liM" / "%liG".

    The thresholds compare |n|; the INT64_MIN quirk is reproduced: its
    absolute value stays INT64_MIN (negative), which is <= 9999 signed,
    so it takes the plain "%li" path.
    """
    a = n if n >= 0 else (-n if n != INT64_MIN else INT64_MIN)
    if a <= 9999:
        return "%d" % n
    if a <= 9999999:
        return "%dK" % trunc_div(n, 1000)
    if a <= 9999999999:
        return "%dM" % trunc_div(n, 1000000)
    return "%dG" % trunc_div(n, 1000000000)


def u64_of_double(value):
    """The unsigned long the formatter passes to the human-size formatter
    for key 3 (SizeBytes).

    Below 2**63 the binary uses plain cvttsd2si; at or above 2**63 it
    subtracts 2**63, converts, and flips bit 63, which is exactly
    trunc(value) mod 2**64 for value in [0, 2**64).  A negative long
    reaches the human-size formatter as its unsigned bit pattern, and
    the formatter's own negative path converts it back the same way,
    so the result is trunc(value) mod 2**64 in every case except NaN
    (INT64_MIN -> 2**63) and value >= 2**64 (the subtract path yields
    0 after the bit flip).
    """
    if math.isnan(value):
        return 1 << 63
    if value >= 2.0 ** 63:
        if value >= 2.0 ** 64:
            return 0
        return cvttsd2si(value - 2.0 ** 63) + (1 << 63)
    return cvttsd2si(value) % (1 << 64)


def human_size(u):
    """The human-size formatter 0x61d0ba0: "%.2f KB|MB|GB|TB".

    u is an unsigned 64-bit byte count.  The value is (double)u, then
    multiplied by 1/1024 until below 1024.0; the TB arm has no further
    check, so an enormous value still prints with TB.
    """
    value = float(u)
    for unit in ("KB", "MB", "GB"):
        value *= 1.0 / 1024.0
        if value < 1024.0:
            return "%.2f %s" % (value, unit)
    value *= 1.0 / 1024.0
    return "%.2f TB" % value


def format_double(value, width, prec):
    """One %<width>.<prec>f conversion, as C printf renders it.

    Python's % formatting rounds the exact binary value the same way
    C does; only NaN needs care: C prints "-nan" when the sign bit is
    set and "nan" otherwise, while Python prints "nan" for both.
    """
    if math.isnan(value):
        negative = struct.pack("<d", value)[7] & 0x80
        body = "-nan" if negative else "nan"
        return "%*s" % (width, body)
    return "%*.*f" % (width, prec, value)


def format_row(label, metrics):
    """Format one data row for the given label and metric map.

    metrics maps keys 1..21 to doubles (the map<int, double> the
    formatter reads).  A missing key raises KeyError, matching the
    binary's __throw_out_of_range("map::at").  The return is the row
    string as the formatter's __snprintf_chk call writes it, including
    the 2000-byte budget (a row longer than 1999 characters is cut).
    """
    def at(key):
        if key not in metrics:
            raise KeyError("map::at: missing metric key %d" % key)
        return metrics[key]

    # Values in format order: label, ints 1-2, size string 3,
    # doubles 4..15, int 16, double 17, int strings 18-19, doubles 20-21.
    values = [label,
              cvttsd2si32(at(1)), cvttsd2si32(at(2)),
              human_size(u64_of_double(at(3)))]
    for key, _w, _p in DOUBLE_COLUMNS[:12]:
        values.append(at(key))
    values.append(cvttsd2si32(at(16)))
    values.append(at(17))
    values.append(int_format(cvttsd2si(at(18))))
    values.append(int_format(cvttsd2si(at(19))))
    for key, _w, _p in DOUBLE_COLUMNS[13:]:
        values.append(at(key))
    # Render conversion by conversion from ROW_FORMAT.
    parts = re.findall(r"%([-0-9.]+[sdif])|([^%]+)", ROW_FORMAT)
    out = []
    vi = 0
    for conv, lit in parts:
        if lit:
            out.append(lit)
            continue
        spec = "%" + conv
        value = values[vi]
        vi += 1
        if conv.endswith("f"):
            width, prec = conv[:-1].split(".")
            out.append(format_double(value, int(width), int(prec)))
        else:
            out.append(spec % value)
    assert vi == len(values), (vi, len(values))
    return "".join(out)[:MAXLEN - 1]


def format_row_bytes(label, metrics):
    """format_row as UTF-8 bytes, as written into the caller's buffer."""
    return format_row(label, metrics).encode("utf-8")
