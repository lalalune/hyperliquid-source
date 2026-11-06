"""Python model of node #115 routine 0x5ef97b0, the third stats-snapshot
consumer (RE-001 work item).

Behaviour (see research/work-items/RE-001-snapshot-consumer-97b0-115/):
the routine takes (owner, out_map).  The owner carries nine u64 counters
at +0x00..0x40, a handler chain at +0x780 and a last timestamp at +0x790;
the out map is a std::map<std::string, std::string> held in the struct at
out+0x08.  For i in 0..8 it writes out[REGISTRY[i]] = decimal(counters[i])
(the name comes from the global int->string registry at 0x65039c8, built
by the static initializer 0x5efbd80), then it walks the handler chain for
a slot return, computes secs = (slot_now - last) / 1e6 as a double and
writes out["db.uptime"] = "%f" % secs.  The single caller is the
23-byte forwarding thunk at 0x5ef9f80, which passes its arguments through
and returns 1.

The decimal conversion is emulated literally from the binary: the
digit-count dispatch, the divide-by-100 magic (0x28f5c28f5c28f5c3) with
the (hi & ~3) + (hi >> 2) adjustment, and the two-digit table.  The
u64-to-double conversion is emulated literally too (the (v >> 1) | (v & 1)
fixup, convert, double).  Both are tested against Python's own str() /
float() on large random samples.
"""

import math

MASK64 = (1 << 64) - 1
MAGIC100 = 0x28F5C28F5C28F5C3
MAGIC10000 = 0x346DC5D63886594B
WALKER = 0x5D4D490

# The global int->string registry at 0x65039c8, keys 0..8, built by the
# static initializer 0x5efbd80 (see derive_names.py in the packet).
REGISTRY = [
    "db.wal_bytes_written",
    "db.wal_syncs",
    "db.user_bytes_written",
    "db.user_keys_written",
    "db.user_writes_by_other",
    "db.user_writes_by_self",
    "db.user_writes_with_wal",
    "db.user_write_stall_micros",
    "write-buffer-manager-limit-stops",
]

# The sibling pair table at 0x6503a00 (keys 1..21), built by the same
# initializer; the consumer does not read it, it is recorded for context.
PAIR_TABLE = [
    (1, "NumFiles", "Files"),
    (2, "CompactedFiles", "CompactedFiles"),
    (3, "SizeBytes", "Size"),
    (4, "Score", "Score"),
    (5, "ReadGB", "Read(GB)"),
    (6, "RnGB", "Rn(GB)"),
    (7, "Rnp1GB", "Rnp1(GB)"),
    (8, "WriteGB", "Write(GB)"),
    (9, "WnewGB", "Wnew(GB)"),
    (10, "MovedGB", "Moved(GB)"),
    (11, "WriteAmp", "W-Amp"),
    (12, "ReadMBps", "Rd(MB/s)"),
    (13, "WriteMBps", "Wr(MB/s)"),
    (14, "CompSec", "Comp(sec)"),
    (15, "CompMergeCPU", "CompMergeCPU(sec)"),
    (16, "CompCount", "Comp(cnt)"),
    (17, "AvgSec", "Avg(sec)"),
    (18, "KeyIn", "KeyIn"),
    (19, "KeyDrop", "KeyDrop"),
    (20, "RblobGB", "Rblob(GB)"),
    (21, "WblobGB", "Wblob(GB)"),
]

# The two-digit table the binary builds on the stack from thirteen
# .rodata chunks (0x451750, 0x453230, 0x456910, 0x453e00, 0x451db0,
# 0x452ba0, 0x455590, 0x456240, 0x456920, 0x4528d0, 0x456250, 0x453240,
# 0x454870); verify.py checks the binary's chunks assemble to this.
DIGIT_TABLE = b"".join(("%02d" % i).encode("ascii") for i in range(100))


def div100(v):
    """Literal emulation of the binary's divide-by-100 step.

    hi = ((v >> 2) * MAGIC100) >> 64; q = hi >> 2;
    rem = v - 20 * ((hi & ~3) + (hi >> 2)).  Returns (q, rem).
    """
    hi = (((v >> 2) * MAGIC100) & ((1 << 128) - 1)) >> 64
    q = hi >> 2
    rem = v - 20 * ((hi & ~3) + (hi >> 2))
    return q, rem


def digit_count(v):
    """Literal emulation of the binary's digit-count dispatch.

    Thresholds 9/99/999/9999, then repeated divide-by-10000 steps
    (magic 0x346dc5d63886594b, >> 75) adding 4 per step, with the
    999999/9999999/99999999 cut-offs adding 5/6/7 to the running count.
    """
    if v <= 9:
        return 1
    if v <= 99:
        return 2
    if v <= 999:
        return 3
    if v <= 9999:
        return 4
    n = 1
    cur = v
    while True:
        q = ((cur * MAGIC10000) & ((1 << 128) - 1)) >> 75
        prev = cur
        cur = q
        eax = n
        n += 4
        if prev <= 99999:
            return n
        if prev <= 999999:
            return eax + 5
        if prev <= 9999999:
            return eax + 6
        if prev <= 99999999:
            return eax + 7


def to_decimal(v):
    """Literal emulation of the binary's u64 -> decimal string.

    Small values take the direct paths (1 digit written outright, 2
    digits from the table); larger values run the divide-by-100 loop
    writing digit pairs from the end of the buffer backwards, then the
    leading one or two digits.
    """
    v &= MASK64
    if v <= 9:
        return chr(ord("0") + v)
    if v <= 99:
        return DIGIT_TABLE[2 * v:2 * v + 2].decode("ascii")
    n = digit_count(v)
    buf = bytearray(n)
    idx = n - 1
    cur = v
    while True:
        q, rem = div100(cur)
        buf[idx] = DIGIT_TABLE[2 * rem + 1]
        buf[idx - 1] = DIGIT_TABLE[2 * rem]
        idx -= 2
        pre = cur
        cur = q
        if pre <= 9999:
            break
    if pre > 999:
        buf[0] = DIGIT_TABLE[2 * cur]
        buf[1] = DIGIT_TABLE[2 * cur + 1]
    else:
        buf[0] = ord("0") + cur
    return buf.decode("ascii")


def u64_to_double(v):
    """Literal emulation of the binary's unsigned u64 -> double.

    Non-negative as signed (v < 2**63): plain cvtsi2sd.  Negative as
    signed: the standard fixup (t = (v >> 1) | (v & 1), convert t,
    double it).  The fixup is exact only for v >= 2**63 -- for small odd
    values it is off by one, which is why the binary branches on the
    sign bit (js at 0x5ef9b6a).  Both paths equal float(v) on their own
    domain; see the tests.
    """
    v &= MASK64
    if v < (1 << 63):
        return float(v)
    t = (v >> 1) | (v & 1)
    return float(t) * 2.0


def format_f(x):
    """C printf("%f") of a double: 6 digits after the point.

    Python's "%.6f" matches C except for NaN: C prints "-nan" for the
    negative (sign-bit-set) QNaN that x86 DIVSD produces, while Python
    prints "nan" for any NaN.
    """
    if math.isnan(x):
        return "-nan" if math.copysign(1.0, x) < 0 else "nan"
    if math.isinf(x):
        return "inf" if x > 0 else "-inf"
    return "%.6f" % x


def select_slot_now(links):
    """The handler-chain walk (main.txt 0x5ef9ae9..0x5ef9b58).

    links is the list of five (slot_addr, return_value) pairs for the
    chain links starting at *(owner+0x780), each next link at +0x20.
    The walk calls the first link whose slot differs from the walker
    0x5d4d490; if all four compared links carry the walker slot, the
    fifth link's slot is called.  Returns the chosen link's return.
    """
    if len(links) != 5:
        raise ValueError("the walk reads exactly five links")
    for slot, value in links[:4]:
        if slot != WALKER:
            return value
    return links[4][1]


def map_at(registry, i):
    """std::map::at(i): the key must exist, else out_of_range ("map::at")."""
    if i not in registry:
        raise ValueError("map::at")
    return registry[i]


def insert_or_assign(out, key, value):
    """The out-map insert-or-assign (lower_bound + map_insert 0x5ef3c80
    on a miss, string move-assign 0x5eebb20 into node+0x40).  In dict
    terms this is plain assignment; a miss creates the entry."""
    out[key] = value


def build_map(counters, slot_now, last):
    """The whole consumer behaviour.  counters is the nine u64 values at
    owner+0x00..0x40; slot_now is the chosen chain slot's return; last
    is owner+0x790.  Returns the out map (dict of str -> str)."""
    if len(counters) != 9:
        raise ValueError("nine counters")
    out = {}
    for i in range(9):
        name = map_at({k: REGISTRY[k] for k in range(9)}, i)
        insert_or_assign(out, name, to_decimal(counters[i]))
    diff = (slot_now - last) & MASK64
    secs = u64_to_double(diff) / 1e6
    insert_or_assign(out, "db.uptime", format_f(secs))
    return out
