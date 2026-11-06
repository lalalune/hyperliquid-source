"""Python model of the node #115 statistics produce path
(RE-001-stats-produce-115).

Models, from the pinned excerpts:
  * StatisticsImpl::ToString 0x6070810 (slot 0xe8 of the
    StatisticsImpl vtable 0x64d2d88): locks the statistics
    mutex at +0x38, reserves 20000 chars, renders one
    "%s COUNT : %lu\\n" line per ticker entry (BSS vector at
    0x6506260) and one "%s P50 : %f P95 : %f P99 : %f P100 :
    %f COUNT : %lu SUM : %lu\\n" line per histogram entry (BSS
    vector at 0x6506240), unlocks, shrinks to fit, returns
    the string.
  * ticker sum 0x6070430: the count for one ticker is the sum
    over 2**shard_bits shards of the u64 at
    shard_base + shard*0xce40 + ticker*8.
  * HistogramData build 0x6070500 + percentiles 0x606bce0:
    a 0x3c8-byte HistogramImpl is allocated per histogram
    entry, the per-shard histograms at
    shard_base + shard*0xce40 + 0x598 + type*0x3c8 are merged
    into it, and the percentile struct is filled. The
    percentile / average / stddev helpers (0x606b500,
    0x606b260, 0x606b540, 0x606b5d0) are NOT pinned whole, so
    their outputs are oracle inputs here: the model pins the
    wiring (which struct field each output lands in, which
    fields the format string prints) exactly as observed.
  * stats emit 0x5d52020: gates on the producer at DB+0x548;
    a null producer emits nothing, otherwise the produce
    call's string is emitted as "[%s:774] STATISTICS:\\n %s".
  * statistics shared_ptr copy site in 0x5d57770: the
    destination's +0x548/+0x550 pair is copied from the
    source's +0x2b8/+0x2c0 via the shared_ptr copy helper
    0x5d35c00 (control pointer copied, use count at +8
    bumped by one).

Conventions: counts are u64 (masked to 64 bits); doubles are
Python floats; the "%f" formatting is C's six-decimal form.
A LengthError is raised when a line would exceed the
0x3fffffffffffffff remaining-capacity check the binary
performs before each append.
"""

MAX_LEN = 0x3FFFFFFFFFFFFFFF
RESERVE = 0x4E20  # 20000, the reserve(0x4e20) in ToString

TICKER_FORMAT = "%s COUNT : %lu\n"
HISTOGRAM_FORMAT = "%s P50 : %f P95 : %f P99 : %f P100 : %f COUNT : %lu SUM : %lu\n"
EMIT_FORMAT = "[%s:774] STATISTICS:\n %s"
EMIT_FILE = "db/db_impl/db_impl.cc"

SHARD_STRIDE = 0xCE40
HISTOGRAM_BASE = 0x598
HISTOGRAM_SIZE = 0x3C8


class LengthError(Exception):
    pass


def _append(out, line):
    """The binary's _M_append gate: remaining capacity is
    0x3fffffffffffffff - len(out); a longer line throws."""
    if len(line) > MAX_LEN - len(out):
        raise LengthError("basic_string: _M_append")
    return out + line


def ticker_sum(shards, shard_bits, ticker):
    """0x6070430: sum over 2**shard_bits shards of the u64 at
    shard_base + shard*0xce40 + ticker*8. `shards` is a list of
    dicts {ticker: count}; missing entries count as 0."""
    total = 0
    for shard in range(1 << shard_bits):
        total += shards[shard].get(ticker, 0)
    return total & 0xFFFFFFFFFFFFFFFF


def ticker_line(name, count):
    """One ticker line, exactly as snprintf formats it."""
    return TICKER_FORMAT % (name, count)


def histogram_data(p50, p95, p99, average, stddev, p100, count, sum_, min_):
    """The 9-field percentile struct 0x606bce0 fills at the
    stack slot (offsets observed, not assumed):
    +0x00 P50, +0x08 P95, +0x10 P99, +0x18 average,
    +0x20 stddev, +0x28 P100, +0x30 count (u64),
    +0x38 sum (u64), +0x40 min (double)."""
    return {
        "p50": p50, "p95": p95, "p99": p99,
        "average": average, "stddev": stddev, "p100": p100,
        "count": count & 0xFFFFFFFFFFFFFFFF,
        "sum": sum_ & 0xFFFFFFFFFFFFFFFF, "min": min_,
    }


def histogram_line(name, data):
    """One histogram line: only P50/P95/P99/P100/count/sum are
    printed; average, stddev and min are computed but not
    printed by this format."""
    return HISTOGRAM_FORMAT % (
        name, data["p50"], data["p95"], data["p99"], data["p100"],
        data["count"], data["sum"])


def statistics_to_string(tickers, histograms, shard_bits):
    """0x6070810 end to end. `tickers` is a list of
    (name, ticker_id, shards); `histograms` is a list of
    (name, hist_type, shards, percentile_oracle) where
    percentile_oracle is a callable returning a histogram_data
    dict for the merged histogram. Returns the string. The
    mutex lock/unlock bracketing is recorded on the trace
    list returned second."""
    trace = ["lock:+0x38"]
    out = ""
    for name, ticker_id, shards in tickers:
        out = _append(out, ticker_line(name, ticker_sum(shards, shard_bits, ticker_id)))
    for name, hist_type, shards, oracle in histograms:
        data = oracle(hist_type, shards)
        out = _append(out, histogram_line(name, data))
    trace.append("unlock:+0x38")
    return out, trace


def stats_emit(producer, file=EMIT_FILE):
    """0x5d52020: null producer -> no emit (empty string, no
    record). Otherwise the produce call's string is emitted
    with the db_impl.cc:774 format. `producer` is None or the
    string the slot-0xe8 callee produced."""
    if producer is None:
        return None
    return EMIT_FORMAT % (file, producer)


def shared_ptr_copy(dst, src):
    """0x5d35c00: copy the control pointer, bump the control's
    use count at +8 by one (plain addl when single-threaded,
    lock addl otherwise). `dst`/`src` are dicts with keys
    'ptr' and 'control' (a dict with 'use_count'); a null
    control is copied without a bump. The helper overwrites
    the destination slot without releasing its old control,
    which matches copy-construction into fresh storage.
    Returns the new use count, or None when there is no
    control."""
    dst["ptr"] = src["ptr"]
    dst["control"] = src["control"]
    if src["control"] is None:
        return None
    src["control"]["use_count"] += 1
    return src["control"]["use_count"]


def stats_copy_site(dst, src):
    """The statistics copy site in 0x5d57770 (0x5d58249..0x5d5828c):
    dst+0x548 = src+0x2b8 (raw pointer), dst+0x550 = src+0x2c0
    (control) via shared_ptr_copy, plus the adjacent 16-byte
    copy dst+0x530..0x540 = src+0x2a0..0x2b0 and the bool
    dst+0x540 = src+0x2b0. `dst`/`src` are dicts keyed by
    offset holding ints; the control is a dict with
    'use_count'. Returns the use count after the copy."""
    dst[0x530] = src[0x2A0]
    dst[0x538] = src[0x2A8]
    dst[0x540] = src[0x2B0] & 0xFF
    raw = {"ptr": src[0x2B8], "control": src[0x2C0]}
    dst_slot = {"ptr": dst.get(0x548), "control": dst.get(0x550)}
    use = shared_ptr_copy(dst_slot, raw)
    dst[0x548] = dst_slot["ptr"]
    dst[0x550] = dst_slot["control"]
    return use


def histogram_delete_check(slot1, known=0x5D8B3B0):
    """The ToString delete check: the histogram object's
    vtable slot 1 is compared against the GOT slot 0x64ed2f0
    (which holds 0x5d8b3b0). Equal -> plain sized delete of
    0x3c8 bytes; different -> virtual call of slot 1."""
    return "direct" if slot1 == known else "virtual"
