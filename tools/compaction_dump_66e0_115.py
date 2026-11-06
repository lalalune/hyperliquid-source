#!/usr/bin/env python3
"""Model of the node #115 compaction-stats dump routine 0x5ef66e0.

The routine (RE-001, work item RE-001-compaction-dump-66e0-115) builds the
whole compaction-stats dump end-to-end and appends it to an output
string: a "Level" header row, one data row per level (plus a "Sum" row),
an "Int" aggregate row, a "Priority" header row, one data row per
priority, blob totals, uptime, flush/addfile lines, cumulative and
interval compaction lines, the "Write Stall" block from sibling
0x5ef6280, and the stats-snapshot consumer block.  The per-level rows
come from the filler 0x5ef1fa0 and the data-row formatter 0x5eed6f0,
modelled in tools/compaction_consumer_a010_115.py and
tools/compaction_data_row_115.py; this module models only the dump
routine's own logic: the label builders, the filler accumulation and
skip rule, the aggregate row, the blob/uptime/flush/addfile/compaction
lines, the stall block, and the update-branch stores.

The decimal conversion (digit-pair table, divide-by-100 and digit-count
dispatch) is the same code as the db-stats consumer
(tools/snapshot_consumer_97b0_115.py, PR #3145): the dump routine's
"L<i>" builder reuses the same thirteen .rodata chunks
(0x451750, 0x453230, 0x456910, 0x453e00, 0x451db0, 0x452ba0, 0x455590,
0x456240, 0x456920, 0x4528d0, 0x456250, 0x453240, 0x454870).

Every u64 -> double conversion in the binary uses the high-bit fixup
(t = (v >> 1) | (v & 1); convert t; double it) when the sign bit is
set; u64_to_double below is that conversion.
"""

MASK64 = (1 << 64) - 1
MAGIC100 = 0x28F5C28F5C28F5C3
MAGIC10000 = 0x346DC5D63886594B

# The two-digit table the binary builds on the stack from thirteen
# .rodata chunks (see the module docstring); verify.py checks the
# binary's chunks assemble to this.
DIGIT_TABLE = b"".join(("%02d" % i).encode("ascii") for i in range(100))

# Priority names assigned by priority_name 0x5fcebc0 (rodata literals
# 0x44fd1a "Bottom", 0x43a5d9 "Low", 0x4409fd "High", 0x4487bb "User",
# 0x432082 "Invalid").
PRIORITY_NAMES = ("Bottom", "Low", "High", "User")

# 192-byte level struct: i64 paddq lanes, a u64 scalar, an i32 scalar,
# then i32 paddd lanes.  Bytes 0xbc..0xbf are not touched by the
# accumulation (the last paddd lane ends at 0xbc).
I64_LANES = (0x00, 0x10, 0x20, 0x30, 0x40, 0x50)
U64_SCALAR = 0x60
I32_SCALAR = 0x68
I32_LANES = (0x6C, 0x7C, 0x8C, 0x9C, 0xAC)
STRUCT_SIZE = 192


def u64(v):
    return v & MASK64


def i64(v):
    v &= MASK64
    return v - (1 << 64) if v >> 63 else v


def u64_to_double(v):
    """The binary's u64 -> double fixup (used whenever the high bit is set)."""
    v &= MASK64
    if v >> 63:
        t = (v >> 1) | (v & 1)
        return float(t) * 2.0
    return float(v)


def div100(v):
    """Literal emulation of the binary's divide-by-100 step."""
    hi = (((v >> 2) * MAGIC100) & ((1 << 128) - 1)) >> 64
    q = hi >> 2
    rem = v - 20 * ((hi & ~3) + (hi >> 2))
    return q, rem


def digit_count(v):
    """Literal emulation of the binary's digit-count dispatch."""
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
    """Literal emulation of the binary's u64 -> decimal string."""
    v &= MASK64
    if v <= 9:
        return chr(ord("0") + v)
    if v <= 99:
        return DIGIT_TABLE[2 * v:2 * v + 2].decode("ascii")
    digits = ["0"] * digit_count(v)
    pos = len(digits)
    while v >= 100:
        v, rem = div100(v)
        pos -= 2
        digits[pos:pos + 2] = DIGIT_TABLE[2 * rem:2 * rem + 2].decode("ascii")
    if v >= 10:
        pos -= 2
        digits[pos:pos + 2] = DIGIT_TABLE[2 * v:2 * v + 2].decode("ascii")
    else:
        pos -= 1
        digits[pos] = chr(ord("0") + v)
    return "".join(digits)


def level_label(index):
    """The "L<i>" label the dump routine builds for level index."""
    return "L" + to_decimal(index)


def priority_name(index):
    """The priority name assigned by priority_name 0x5fcebc0."""
    if 0 <= index <= 3:
        return PRIORITY_NAMES[index]
    return "Invalid"


def priority_count(begin, end):
    """Number of 192-byte priority structs in [begin, end)."""
    return (end - begin) // STRUCT_SIZE


def filler_skip(first16_zero, elem_count):
    """The filler's skip rule: skip a level whose first 16 bytes are
    both zero AND whose element count is 0.  (Its elem/flagged counts
    still join the Sum totals; its S and dense do not.)"""
    return bool(first16_zero) and elem_count == 0


def _add_i64(buf, off, value):
    cur = int.from_bytes(buf[off:off + 8], "little", signed=True)
    buf[off:off + 8] = (cur + value).to_bytes(8, "little", signed=True)


def _add_i32(buf, off, value):
    cur = int.from_bytes(buf[off:off + 4], "little", signed=True)
    buf[off:off + 4] = (cur + value).to_bytes(4, "little", signed=True)


def accumulate_192(dst, src):
    """Lane-wise accumulation of one 192-byte level struct into dst
    (the filler's snapshot accumulation; dst and src are bytearrays of
    192 bytes).  Returns dst."""
    for off in I64_LANES:
        for lane in (off, off + 8):
            _add_i64(dst, lane, i64(int.from_bytes(src[lane:lane + 8], "little")))
    _add_i64(dst, U64_SCALAR,
             i64(int.from_bytes(src[U64_SCALAR:U64_SCALAR + 8], "little")))
    _add_i32(dst, I32_SCALAR,
             int.from_bytes(src[I32_SCALAR:I32_SCALAR + 4], "little", signed=True))
    for off in I32_LANES:
        for lane in (off, off + 4, off + 8, off + 12):
            _add_i32(dst, lane,
                     int.from_bytes(src[lane:lane + 4], "little", signed=True))
    return dst


def diff_192(cur, prev):
    """Lane-wise difference of two 192-byte structs (the "Int" row's
    aggregate: current snapshot minus the previous snapshot)."""
    out = bytearray(STRUCT_SIZE)
    for off in I64_LANES:
        for lane in (off, off + 8):
            a = int.from_bytes(cur[lane:lane + 8], "little", signed=True)
            b = int.from_bytes(prev[lane:lane + 8], "little", signed=True)
            out[lane:lane + 8] = (a - b).to_bytes(8, "little", signed=True)
    a = int.from_bytes(cur[U64_SCALAR:U64_SCALAR + 8], "little", signed=True)
    b = int.from_bytes(prev[U64_SCALAR:U64_SCALAR + 8], "little", signed=True)
    out[U64_SCALAR:U64_SCALAR + 8] = (a - b).to_bytes(8, "little", signed=True)
    a = int.from_bytes(cur[I32_SCALAR:I32_SCALAR + 4], "little", signed=True)
    b = int.from_bytes(prev[I32_SCALAR:I32_SCALAR + 4], "little", signed=True)
    out[I32_SCALAR:I32_SCALAR + 4] = (a - b).to_bytes(4, "little", signed=True)
    for off in I32_LANES:
        for lane in (off, off + 4, off + 8, off + 12):
            a = int.from_bytes(cur[lane:lane + 4], "little", signed=True)
            b = int.from_bytes(prev[lane:lane + 4], "little", signed=True)
            out[lane:lane + 4] = (a - b).to_bytes(4, "little", signed=True)
    return bytes(out)


def struct_i64(buf, off):
    return int.from_bytes(buf[off:off + 8], "little", signed=True)


def sum_s(elements):
    """The filler's S_i: sum over the non-null elements of a level's
    vector of *(element + 0x10) as i64.  elements is a list of
    (is_null, value_at_plus_0x10)."""
    total = 0
    for is_null, value in elements:
        if not is_null:
            total = (total + value) & MASK64
    return i64(total)


def ratio_for_level(level, index, owner_flush_cum, owner_addfile_cum):
    """The filler's per-level ratio.

    CORRECTED vs open PR #3164 (which claims "0.0 for level 0"): the
    level-0 denominator is owner+0x90 + owner+0x98, not zero.  The
    branch at filler 0x5ef22a2 only skips reloading the denominator
    from L+0x20+L+0x10; the division still runs when the owner sum is
    nonzero.  For level i != 0 the denominator is L+0x20+L+0x10.
    The numerator is L+0x30+L+0x28 in both cases; 0.0 when the
    denominator is 0.
    """
    numer = u64(struct_i64(level, 0x30) + struct_i64(level, 0x28))
    if index == 0:
        denom = u64(owner_flush_cum + owner_addfile_cum)
    else:
        denom = u64(struct_i64(level, 0x20) + struct_i64(level, 0x10))
    if denom == 0:
        return 0.0
    return u64_to_double(numer) / u64_to_double(denom)


def sum_ratio(snapshot, owner_flush_cum, owner_addfile_cum):
    """The filler's Sum-node ratio: (snap+0x30+snap+0x28) /
    (owner+0x90+owner+0x98), or 0.0 when that sum is 0."""
    numer = u64(struct_i64(snapshot, 0x30) + struct_i64(snapshot, 0x28))
    denom = u64(owner_flush_cum + owner_addfile_cum)
    if denom == 0:
        return 0.0
    return u64_to_double(numer) / u64_to_double(denom)


def aggregate_ratio(agg, flush_interval, addfile_interval):
    """The "Int" row's ratio: (agg+0x30+agg+0x28) /
    (1 + flush_interval + addfile_interval).  The denominator is
    always >= 1, so there is no zero guard here."""
    numer = u64(struct_i64(agg, 0x30) + struct_i64(agg, 0x28))
    denom = u64(1 + flush_interval + addfile_interval)
    return u64_to_double(numer) / u64_to_double(denom)


def blob_line(count, total, garbage):
    """The blob totals line (format 0x957c88):
    "\\nBlob file count: %zu, total size: %.1f GB, garbage size: %.1f GB,
    space amp: %.1f\\n\\n".  space amp is total/(total-garbage) when
    garbage < total, else 0.0."""
    total_gb = u64_to_double(total) * 2.0 ** -30
    garbage_gb = u64_to_double(garbage) * 2.0 ** -30
    if garbage < total:
        space_amp = u64_to_double(total) / u64_to_double(total - garbage)
    else:
        space_amp = 0.0
    return ("\nBlob file count: %d, total size: %.1f GB, "
            "garbage size: %.1f GB, space amp: %.1f\n\n"
            % (count, total_gb, garbage_gb, space_amp))


def uptime_line(now_us, prev_total_us, owner700):
    """The uptime line (format 0x9621a8):
    "Uptime(secs): %.1f total, %.1f interval\\n".  total_secs is
    (now - prev_total) / 1e6; interval_secs is total_secs - owner+0x700."""
    total_secs = i64(now_us - prev_total_us) / 1e6
    interval_secs = total_secs - owner700
    return "Uptime(secs): %.1f total, %.1f interval\n" % (total_secs, interval_secs)


def flush_line(cum, prev):
    """The flush line (format 0x95a548):
    "Flush(GB): cumulative %.3f, interval %.3f\\n"."""
    return ("Flush(GB): cumulative %.3f, interval %.3f\n"
            % (u64_to_double(cum) * 2.0 ** -30,
               u64_to_double(u64(cum - prev)) * 2.0 ** -30))


def addfile_gb_line(cum, prev):
    """The AddFile(GB) line (format 0x9661b0)."""
    return ("AddFile(GB): cumulative %.3f, interval %.3f\n"
            % (u64_to_double(cum) * 2.0 ** -30,
               u64_to_double(u64(cum - prev)) * 2.0 ** -30))


def addfile_count_line(kind, cum, prev):
    """The AddFile(Total Files) / (L0 Files) / (Keys) lines
    (formats 0x964030, 0x95cf78, 0x9590d0):
    "AddFile(<kind>): cumulative %lu, interval %lu\\n".  The interval
    is a u64 subtraction, so it wraps when cum < prev."""
    return ("AddFile(%s): cumulative %d, interval %d\n"
            % (kind, u64(cum), u64(cum - prev)))


def compaction_lines(write_total, read_total, secs_total, uptime_total,
                     write_prev, read_prev, secs_prev, interval_secs):
    """The cumulative and interval compaction lines (formats 0x964aa8
    and 0x964b10).  Each MB/s divisor is max(uptime, 0.001): when the
    uptime is below 0.001 the binary divides by 0.001 instead."""
    cum_div = uptime_total if uptime_total >= 0.001 else 0.001
    int_div = interval_secs if interval_secs >= 0.001 else 0.001
    cumulative = ("Cumulative compaction: %.2f GB write, %.2f MB/s write, "
                  "%.2f GB read, %.2f MB/s read, %.1f seconds\n"
                  % (u64_to_double(write_total) * 2.0 ** -30,
                     (u64_to_double(write_total) * 2.0 ** -20) / cum_div,
                     u64_to_double(read_total) * 2.0 ** -30,
                     (u64_to_double(read_total) * 2.0 ** -20) / cum_div,
                     secs_total / 1e6))
    interval = ("Interval compaction: %.2f GB write, %.2f MB/s write, "
                "%.2f GB read, %.2f MB/s read, %.1f seconds\n"
                % (u64_to_double(u64(write_total - write_prev)) * 2.0 ** -30,
                   (u64_to_double(u64(write_total - write_prev)) * 2.0 ** -20) / int_div,
                   u64_to_double(u64(read_total - read_prev)) * 2.0 ** -30,
                   (u64_to_double(u64(read_total - read_prev)) * 2.0 ** -20) / int_div,
                   i64(secs_total - secs_prev) / 1e6))
    return cumulative, interval


def parse_u64(text):
    """The decimal-string -> u64 parser 0x61d1540 (strtoull base 10
    semantics on the well-formed path): leading whitespace and an
    optional sign are skipped, digits are consumed, no digits yields 0,
    overflow clamps to 2^64-1."""
    i = 0
    n = len(text)
    while i < n and text[i] in " \t\n\v\f\r":
        i += 1
    sign = 1
    if i < n and text[i] in "+-":
        if text[i] == "-":
            sign = -1
        i += 1
    value = 0
    any_digit = False
    while i < n and text[i].isdigit():
        any_digit = True
        value = value * 10 + (ord(text[i]) - ord("0"))
        if value > MASK64:
            value = MASK64
            while i < n and text[i].isdigit():
                i += 1
            break
        i += 1
    if not any_digit:
        return 0
    if sign < 0:
        return (-value) & MASK64
    return value


def stall_sum(stops_text, delays_text):
    """The stall total: parse_u64("total-stops") + parse_u64("total-delays")."""
    return u64(parse_u64(stops_text) + parse_u64(delays_text))


def stall_interval_line(total, prev):
    """The sibling 0x5ef6280 interval line, appended only when the
    stall total is nonzero: "interval: <total - prev> total count\\n"."""
    if total == 0:
        return ""
    return "interval: %d total count\n" % u64(total - prev)
