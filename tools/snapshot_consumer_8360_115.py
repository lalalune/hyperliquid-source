#!/usr/bin/env python3
"""Model of the node #115 stats-snapshot consumer 0x5ef8360.

The routine fills a std::map<std::string, std::string> (held at ctx+0x08)
from a 312-byte stats snapshot.  It is the sibling of the twin consumer
0x5eefda0 (open PR #3082), which renders the same snapshot as text; this
one instead stores every number under a string key.  See
research/work-items/RE-001-snapshot-consumer-8360-115/README.md and
records.json for the evidence.

Model inputs: a snapshot dict (the fields the routine reads) and the
chain head's slot +0x98 return (slot_now).  The model reproduces the
routine's arithmetic exactly, including the unsigned-to-double fixup,
the magic /1e6 division, the "%f" formatting and the digit-pair
u64-to-decimal conversion.
"""

import math
import struct

MASK64 = (1 << 64) - 1

# The 14 role names, in slot order (research/work-items/.../records.json
# name_table).  The table at 0x6503c00 holds std::string objects built at
# load by the initializer 0x5f007f0 from these literals.
ROLE_NAMES = [
    "data-block",
    "filter-block",
    "filter-meta-block",
    "deprecated-filter-block",
    "index-block",
    "other-block",
    "write-buffer",
    "compression-dictionary-building-buffer",
    "filter-construction",
    "block-based-table-reader",
    "file-metadata",
    "blob-value",
    "blob-cache",
    "misc",
]

# The digit-pair table the binary copies to its stack (rsp+0xa0) and the
# standalone helper 0x5d4f970 uses: "00", "01", ..., "99".  Verified
# byte-for-byte against the .rodata chunks the binary copies.
_DIGIT_PAIRS = "".join("%02d" % i for i in range(100))

_DIV_MAGIC = 0x431BDE82D7B634DB

# The x86 DIVSD indefinite QNaN (0.0 / 0.0): sign bit set, exponent and
# mantissa all ones in the top bits.
_QNAN_NEG = struct.unpack("<d", struct.pack("<Q", 0xFFF8000000000000))[0]


def to_string_u64(value):
    """The binary's u64-to-decimal conversion (0x5d4f970, and the same
    code inlined three times per slot in 0x5ef8360).

    The magnitude branches pick the digit count (1..7 for the fast path,
    then 8..20 through the /10 loop), _M_construct allocates that many
    NULs, and the pair loop fills the buffer from the end two digits at
    a time using the digit-pair table.  The result equals str(value) for
    every u64; the tests check it against str() on 200,000 values.
    """
    value &= MASK64
    if value <= 9:
        return chr(0x30 + value)
    # General path: repeated /100, two digits at a time from the end.
    parts = []
    v = value
    while v > 99:
        parts.append(_DIGIT_PAIRS[(v % 100) * 2:(v % 100) * 2 + 2])
        v //= 100
    if v > 9:
        parts.append(_DIGIT_PAIRS[v * 2:v * 2 + 2])
    else:
        parts.append(chr(0x30 + v))
    return "".join(reversed(parts))


def u64_to_f64(value):
    """The binary's unsigned-to-double conversion (cvtsi2sd plus the
    sign-bit fixup at 0x5ef8424/0x5ef9383, 0x5ef8cb5/0x5ef9140 and
    0x5ef8cd1/0x5ef9120): for v >= 2**63 the fixup path takes
    t = (v >> 1) | (v & 1), converts t, and doubles it.  This is the
    standard correctly-rounded unsigned conversion: it agrees with
    float(v) on 200,000 random 64-bit values with no difference, so the
    branch is reproduced literally rather than short-circuited.
    """
    value &= MASK64
    if value < (1 << 63):
        return float(value)
    t = (value >> 1) | (value & 1)
    d = float(t)
    return d + d


def elapsed_ns(last_value, prev_value):
    """The 0x5eee580 helper (elapsed.txt): last - prev when prev < last,
    else 0.  Unsigned 64-bit arithmetic.

    CORRECTION to open PR #3082: its model and tests say "else last".
    The code is `mov $0x0,%edx; cmovae %rdx,%rax` (0x5eee59b/0x5eee5a0),
    and rdx was just zeroed, so the else branch returns 0, not last.
    """
    last_value &= MASK64
    prev_value &= MASK64
    if prev_value < last_value:
        return (last_value - prev_value) & MASK64
    return 0


def divide_by_1e6(value):
    """The magic multiply at 0x5ef849f: (x * 0x431bde82d7b634db >> 64) >> 18.

    Verified against x // 1_000_000 on 200,010 values (0, 1, 10**6 - 1,
    10**6, 2**63, 2**64 - 1 and 200,000 random 64-bit values): no mismatch.
    """
    value &= MASK64
    return (((value * _DIV_MAGIC) >> 64) & MASK64) >> 18


def format_pct(value):
    """The "%f" formatting the 0x5eec680 helper produces (format "%f" at
    0x432165): six digits after the point, C rounding.

    Python's %.6f drops the sign of a NaN, so the negative QNaN the
    binary's DIVSD produces for 0.0/0.0 is restored explicitly, the way
    the twin's format_g6 does for %g.
    """
    if math.isnan(value):
        return "-nan" if math.copysign(1.0, value) < 0 else "nan"
    return "%.6f" % value


def build_map(snapshot, slot_now):
    """Fill the ctx map from a snapshot, the way 0x5ef8360 does.

    snapshot: dict with name (str), capacity (u64), prev_value (u64),
    last_value (u64), counts (14 u64, snapshot+0xb0) and values
    (14 u64, snapshot+0x40).  slot_now: the chain head's slot +0x98
    return.  Returns the map as a dict in construction order (the
    binary's std::map iterates in sorted-key order, which this model
    does not pin because the routine itself never iterates the map).

    The routine writes all 46 entries unconditionally: the four header
    entries, then three per slot ("count." / "bytes." / "percent." plus
    the role name) for all 14 slots, including zero counts.
    """
    out = {}
    # Header (main.txt 0x5ef83cd..0x5ef84ea).
    out["di"] = snapshot["name"]
    out["capacity"] = to_string_u64(snapshot["capacity"])
    ratio = u64_to_f64(elapsed_ns(snapshot["last_value"],
                                   snapshot["prev_value"])) / 1e6
    out["secs_for_last_collection"] = format_pct(ratio)
    secs_since = divide_by_1e6(
        (slot_now - snapshot["last_value"]) & MASK64)
    out["secs_since_last_collection"] = to_string_u64(secs_since)
    # Entry loop (main.txt 0x5ef84ef..0x5ef8ec8): 14 slots.
    capacity = snapshot["capacity"]
    for i, role in enumerate(ROLE_NAMES):
        count = snapshot["counts"][i] & MASK64
        value = snapshot["values"][i] & MASK64
        out["count." + role] = to_string_u64(count)
        out["bytes." + role] = to_string_u64(value)
        if capacity == 0:
            portion = math.inf if value > 0 else _QNAN_NEG
        else:
            portion = u64_to_f64(value) * 100.0 / u64_to_f64(capacity)
        out["percent." + role] = format_pct(portion)
    return out
