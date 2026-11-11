"""Python model of node #115 routines 0x5efa010 (main), 0x5ef1fa0 (filler),
0x5ef1630 (metric insert) and 0x5ef5d40 (summary consumer) (RE-001 work
item).

Behaviour (see research/work-items/RE-001-compaction-consumer-a010-115/):
the main routine takes (owner, out_map).  It calls the filler, which
builds an outer map<std::map<int, std::map<int, double>>> keyed by level
marker (one entry per level plus a "Sum" entry with key -1) whose inner
maps hold 21 per-level compaction metrics (ids 1..21, inserted by
0x5ef1630), then walks the outer map and writes, for every (level,
metric) pair, out["compaction." + label + "." + name] = "%f" % value,
where label is "Sum" for marker -1 else "L" + decimal(marker) and name
is the metric's internal name from the global pair map at 0x6503a00
(keys 1..21, built by the static initializer 0x5efbd80).  It then calls
the summary consumer 0x5ef5d40, which writes seven further entries
(three tag-selected counters plus two ongoing-compaction counters and
the total-stops / total-delays aggregates) as decimal strings.

The decimal conversion is emulated literally from the binary: the
digit-count dispatch, the divide-by-100 magic (0x28f5c28f5c28f5c3) with
the (hi & ~3) + (hi >> 2) adjustment, and the two-digit table (the same
table and magics the summary consumer's own u64->string helper 0x5d4f970
uses).  The u64-to-double conversion is emulated literally too (the
(v >> 1) | (v & 1) fixup, convert, double).  Both are tested against
Python's own str() / float() on large random samples.
"""

import math

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
MAGIC100 = 0x28F5C28F5C28F5C3
MAGIC10000 = 0x346DC5D63886594B
K2_30 = 9.313225746154785e-10  # 2**-30, .rodata 0x459c48
K2_20 = 9.5367431640625e-07    # 2**-20, .rodata 0x459638
ONE_MILLION = 1000000.0        # .rodata 0x4599a0

# The global pair map at 0x6503a00: std::map<int, std::pair<std::string,
# std::string>>, keys 1..21, built by the static initializer 0x5efbd80
# (see derive_names.py in the packet).  The main routine reads the FIRST
# string (the internal name) through map::at; the sibling formatter
# 0x5eedda0 reads the SECOND string (the display name) for its columns.
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
PAIR_FIRST = {k: first for k, first, _ in PAIR_TABLE}
PAIR_SECOND = {k: second for k, _, second in PAIR_TABLE}

# The two-digit table the binary builds on the stack from thirteen
# .rodata chunks (0x451750, 0x453230, 0x456910, 0x453e00, 0x451db0,
# 0x452ba0, 0x455590, 0x456240, 0x456920, 0x4528d0, 0x456250, 0x453240,
# 0x454870); verify.py checks the binary's chunks assemble to this.
DIGIT_TABLE = b"".join(("%02d" % i).encode("ascii") for i in range(100))

# Level-struct fields used by the metric insert, by offset from the
# struct base (owner+0x138 + level*0xc0).  The snapshot accumulates the
# same fields lane-wise (paddq for the i64 lanes, paddd for the i32 at
# +0x68); the model keeps the snapshot as a dict of the same shape.
LEVEL_FIELDS = ("f00", "f08", "f10", "f18", "f20", "f28", "f30", "f38",
                "f50", "f58", "f60", "f68")
I32_FIELDS = ("f68",)


def s32(v):
    """Interpret the low 32 bits as a signed 32-bit int."""
    v &= MASK32
    return v - (1 << 32) if v >= (1 << 31) else v


def s64(v):
    """Interpret the low 64 bits as a signed 64-bit int."""
    v &= MASK64
    return v - (1 << 64) if v >= (1 << 63) else v


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
    double it).  Both paths equal float(v) on their own domain.
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


def div_double(a, b):
    """x86 DIVSD semantics: a / b, with a / 0.0 yielding +inf / -inf for
    nonzero a and a (sign-bit-set) QNaN for 0.0 / 0.0, as the binary's
    divsd does (Python's float division raises instead)."""
    if b == 0.0:
        if a == 0.0 or math.isnan(a):
            return math.copysign(float("nan"), -1.0)
        return math.copysign(float("inf"), math.copysign(1.0, a))
    return a / b


def map_at(registry, i):
    """std::map::at(i): the key must exist, else out_of_range ("map::at")."""
    if i not in registry:
        raise ValueError("map::at")
    return registry[i]


def insert_or_assign(out, key, value):
    """The out-map insert-or-assign (lower_bound + map_node_create
    0x5ef3ed0 on a miss, string move-assign 0x5eebb20 into node+0x40).
    In dict terms this is plain assignment; a miss creates the entry."""
    out[key] = value


def scalar_sum(entries):
    """0x5f6c300 -> 0x5da4de0: sum of +0x10 over the non-null pointers
    in [begin, end).  entries is a list of (is_null, plus10_value)."""
    total = 0
    for is_null, value in entries:
        if not is_null:
            total = (total + value) & MASK64
    return total


def level_skip(level, elem_count):
    """The filler's per-level skip (filler.txt 0x5ef2197..0x5ef21aa):
    a level is skipped (no snapshot accumulation, no metric insert, no
    outer-map node) when its first 16 bytes are both zero and it has no
    elements.  Its elem/flagged counts still join the Sum totals."""
    return level["f00"] == 0 and level["f08"] == 0 and elem_count <= 0


def ratio_for_level(level, level_index):
    """The filler's per-level ratio (filler.txt 0x5ef22e2..0x5ef2329):
    0.0 for level 0 or when (L+0x20 + L+0x10) is 0, else
    (double)(L+0x30 + L+0x28) / (double)(L+0x20 + L+0x10)."""
    if level_index == 0:
        return 0.0
    den = (level["f20"] + level["f10"]) & MASK64
    if den == 0:
        return 0.0
    num = (level["f30"] + level["f28"]) & MASK64
    return u64_to_double(num) / u64_to_double(den)


def metric_values(level, elem_count, flagged_count, s_value, dense,
                  ratio):
    """0x5ef1630: the 21 metric values for one level struct.

    level is a dict of the LEVEL_FIELDS (i64 values, f68 an i32);
    elem_count / flagged_count are the i32 counts; s_value is the
    0x5f6c300 sum as a double; dense is the dense double; ratio is the
    filler ratio.  Returns {metric_id: float} for ids 1..21.
    """
    f = level
    rdx_total = (f["f10"] + f["f18"] + f["f20"]) & MASK64
    r14_total = (f["f28"] + f["f30"]) & MASK64
    base = u64_to_double((f["f00"] + 1) & MASK64) / ONE_MILLION
    f68 = s32(f["f68"])
    return {
        1: float(s32(elem_count)),
        2: float(s32(flagged_count)),
        3: s_value,
        4: dense,
        5: u64_to_double(rdx_total) * K2_30,
        6: u64_to_double(f["f10"]) * K2_30,
        7: u64_to_double(f["f18"]) * K2_30,
        8: u64_to_double(f["f28"]) * K2_30,
        9: u64_to_double((f["f28"] - f["f18"]) & MASK64) * K2_30,
        10: u64_to_double(f["f38"]) * K2_30,
        11: ratio,
        12: div_double(u64_to_double(rdx_total) * K2_20, base),
        13: div_double(u64_to_double(r14_total) * K2_20, base),
        14: u64_to_double(f["f00"]) / ONE_MILLION,
        15: u64_to_double(f["f08"]) / ONE_MILLION,
        16: float(f68),
        17: 0.0 if f68 == 0 else
            div_double(u64_to_double(f["f00"]) / ONE_MILLION, float(f68)),
        18: u64_to_double(f["f50"]),
        19: u64_to_double(f["f58"]),
        20: u64_to_double(f["f20"]) * K2_30,
        21: u64_to_double(f["f30"]) * K2_30,
    }


def snapshot_add(snapshot, level):
    """Lane-wise accumulation of one level struct into the snapshot
    (filler.txt 0x5ef21b0..0x5ef229b): paddq for the i64 lanes, paddd
    for the i32 at +0x68.  Returns a new snapshot dict."""
    out = {}
    for field in LEVEL_FIELDS:
        if field in I32_FIELDS:
            out[field] = s32(snapshot[field] + level[field])
        else:
            out[field] = (snapshot[field] + level[field]) & MASK64
    return out


def zero_level():
    """An all-zero level struct / snapshot."""
    return {field: 0 for field in LEVEL_FIELDS}


def sum_ratio(snapshot, owner90, owner98):
    """The Sum node's ratio (filler.txt 0x5ef251a..0x5ef2565): 0.0 when
    (owner+0x90 + owner+0x98) is 0, else (double)(snap+0x30 +
    snap+0x28) / (double)(owner+0x90 + owner+0x98)."""
    den = (owner90 + owner98) & MASK64
    if den == 0:
        return 0.0
    num = (snapshot["f30"] + snapshot["f28"]) & MASK64
    return u64_to_double(num) / u64_to_double(den)


def fill_outer(levels, per_level, owner90, owner98):
    """The filler 0x5ef1fa0 (normal path): builds the outer map
    {marker: {metric_id: float}}.

    levels is the list of level structs (dicts of LEVEL_FIELDS);
    per_level is the parallel list of (elem_count, flagged_count,
    s_value, dense); owner90/owner98 are the owner u64s at +0x90/+0x98.
    A level is skipped by level_skip; the Sum node (marker -1) is
    inserted unconditionally, its metrics computed from the accumulated
    snapshot with the summed elem/flagged/S totals and dense 0.0.
    """
    if len(levels) != len(per_level):
        raise ValueError("levels and per_level must be parallel")
    outer = {}
    snapshot = zero_level()
    elem_total = 0
    flagged_total = 0
    s_total = 0.0
    for index, (level, (elem, flagged, s_value, dense)) in enumerate(
            zip(levels, per_level)):
        elem_total = (elem_total + s32(elem)) & MASK32
        flagged_total = (flagged_total + s32(flagged)) & MASK32
        if level_skip(level, elem):
            continue
        snapshot = snapshot_add(snapshot, level)
        s_total += s_value
        outer[index] = metric_values(
            level, elem, flagged, s_value, dense,
            ratio_for_level(level, index))
    # The Sum node: totals, snapshot, dense 0.0 (filler.txt 0x5ef251a..).
    outer[-1] = metric_values(
        snapshot, s32(elem_total), s32(flagged_total), s_total, 0.0,
        sum_ratio(snapshot, owner90, owner98))
    return outer


def label_for(marker):
    """The main routine's level label (main.txt 0x5efa3a0..0x5efa440):
    "Sum" for marker -1, else "L" + decimal(marker)."""
    if marker == -1:
        return "Sum"
    return "L" + to_decimal(marker)


def compaction_key(label, metric_name):
    """The out-map key: "compaction." + label + "." + name."""
    return "compaction." + label + "." + metric_name


def emit_compaction_stats(outer, name_map=None):
    """The main routine 0x5efa010: outer map -> out map.

    outer is {marker: {metric_id: float}}; name_map is the metric-id ->
    internal-name table (defaults to the global pair map's first
    strings).  Returns the out map (dict of str -> str), values
    formatted with "%f" (6 decimal places)."""
    names = PAIR_FIRST if name_map is None else name_map
    out = {}
    for marker in sorted(outer):
        label = label_for(marker)
        for metric_id in sorted(outer[marker]):
            name = map_at(names, metric_id)
            key = compaction_key(label, name)
            insert_or_assign(out, key,
                             format_f(outer[marker][metric_id]))
    return out


def tag_index(i, ebp):
    """0x5fc9e20: the (i, ebp) -> tag table.  Returns 0xe (skip) for
    out-of-range inputs."""
    if i == 0:
        return 0 if ebp == 0 else 1 if ebp == 1 else 0xE
    if i == 1:
        return 2 if ebp == 0 else 3 if ebp == 1 else 0xE
    if i == 2:
        return 4 if ebp == 0 else 5 if ebp == 1 else 0xE
    return 0xE


def part_a(i):
    """0x5fc9960: the first half of a summary name, for i in {0,1,2,4}."""
    names = {
        0: "memtable-limit",
        1: "l0-file-count-limit",
        2: "pending-compaction-bytes",
        4: "write-buffer-manager-limit",
    }
    if i not in names:
        raise ValueError("part_a undefined for %d" % i)
    return names[i]


def part_b(ebp):
    """0x5fc9ce0: the second half of a summary name, for ebp in {0,1}."""
    if ebp == 0:
        return "delays"
    if ebp == 1:
        return "stops"
    raise ValueError("part_b undefined for %d" % ebp)


def name_builder(i, ebp):
    """0x5fca2d0: part_a(i) + "-" + part_b(ebp), defined only when the
    gates (i <= 2 or i == 4) and (ebp in {0, 1}) pass; else ""."""
    if not (i <= 2 or i == 4):
        return ""
    if ebp not in (0, 1):
        return ""
    return part_a(i) + "-" + part_b(ebp)


def final_summary(owner):
    """The summary consumer 0x5ef5d40: owner fields -> the seven
    trailing out-map entries.

    owner is a dict keyed by offset: 0xb8, 0xd0, 0xe0 (tag-selected
    counters: owner+0xb8 + tag*8 for tags 0, 3, 5), 0xe8, 0xf0
    (ongoing-compaction counters).  Returns the
    out map (dict of str -> str), values as decimal strings."""
    out = {}
    delays_total = 0
    stops_total = 0
    ebp = 0
    for i in range(3):
        tag = tag_index(i, ebp)
        if tag == 0xE:
            ebp = 1
            continue
        value = owner[0xB8 + tag * 8]
        insert_or_assign(out, name_builder(i, ebp), to_decimal(value))
        if ebp == 0:
            delays_total = (delays_total + value) & MASK64
        else:
            stops_total = (stops_total + value) & MASK64
        ebp = 1
    insert_or_assign(
        out, "cf-l0-file-count-limit-delays-with-ongoing-compaction",
        to_decimal(owner[0xE8]))
    insert_or_assign(
        out, "cf-l0-file-count-limit-stops-with-ongoing-compaction",
        to_decimal(owner[0xF0]))
    insert_or_assign(out, "total-stops", to_decimal(stops_total))
    insert_or_assign(out, "total-delays", to_decimal(delays_total))
    return out


def build_map(levels, per_level, owner90, owner98, owner_fields):
    """The whole behaviour end to end: filler + main emission + the
    summary consumer.  Returns the merged out map."""
    outer = fill_outer(levels, per_level, owner90, owner98)
    out = emit_compaction_stats(outer)
    out.update(final_summary(owner_fields))
    return out
