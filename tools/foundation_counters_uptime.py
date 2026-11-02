"""Model for node #94 0x5159180 (RE-001-counters-uptime-94).

The window renders nine outer counters into a keyed report map
through a name map, then appends one ``db.uptime`` entry from the
clock. The expectations are transcribed from the window's
disassembly (see research/work-items/RE-001-counters-uptime-94/):
the digit-count ladder and digit-pair fill of the inlined itoa,
the map::at name lookup, the 3-node clock dispatch chain, the
unsigned elapsed conversion, and the "%f" uptime formatting.

The tests pin the model, not an execution of the target binary
(no execution is available here). The nine names are runtime
parameters: the global map at 0x578bee0 is zero in the file.
"""

ENTRY_COUNT = 9
UPTIME_KEY = b"db.uptime"
USIZE = 1 << 64
SENTINEL_DEFAULT = None  # the caller supplies the cell's runtime value

PAIR_TABLE = ["%02d" % i for i in range(100)]


def digit_count(value):
    """Digit count exactly as the window's ladder computes it.

    <= 9 / 99 / 999 / 9999 give 1 / 2 / 3 / 4 digits; larger
    values loop dividing by 10000 (4 more digits per step) with
    remainder arms at 999999 / 9999999 / 99999999 adding 5 / 6 / 7
    to the previous count.
    """
    if value <= 9:
        return 1
    if value <= 99:
        return 2
    if value <= 999:
        return 3
    if value <= 9999:
        return 4
    count = 1
    current = value
    while True:
        previous = count
        count += 4
        if current > 99999:
            if current <= 999999:
                return previous + 5
            if current <= 9999999:
                return previous + 6
            if current <= 99999999:
                return previous + 7
            current //= 10000
        else:
            return count


def itoa(value):
    """Unsigned decimal rendering via the window's pair fill.

    Pairs are written from the end per divide-by-100 step while
    the pre-step value exceeds 9999; the tail writes two digits
    when the pre-step value exceeds 999, else one digit.
    """
    count = digit_count(value)
    if count == 1:
        return chr(ord("0") + value)
    if count == 2:
        return PAIR_TABLE[value]
    buf = [""] * count
    pos = count - 1
    current = value
    while True:
        pre = current
        pair = PAIR_TABLE[current % 100]
        buf[pos - 1] = pair[0]
        buf[pos] = pair[1]
        pos -= 2
        current //= 100
        if pre <= 9999:
            break
    if pre > 999:
        pair = PAIR_TABLE[current]
        buf[0] = pair[0]
        buf[1] = pair[1]
    else:
        buf[0] = chr(ord("0") + current)
    return "".join(buf)


def saturate_length_diff(diff):
    """Clamp a key-length difference to int32, as the walks do.

    Differences at or above 2**31 land on the positive side and
    differences at or below -2**31 - 1 on the negative side.
    """
    if diff >= 1 << 31:
        return (1 << 31) - 1
    if diff <= -(1 << 31) - 1:
        return -(1 << 31)
    return diff


def compare_keys(key, literal):
    """Sign of (key vs literal) under the window's comparison.

    memcmp over the common prefix (unsigned bytes, as in C), then
    the length difference saturated to int32. Returns -1, 0 or 1.
    """
    common = min(len(key), len(literal))
    if key[:common] != literal[:common]:
        return -1 if key[:common] < literal[:common] else 1
    diff = saturate_length_diff(len(key) - len(literal))
    if diff < 0:
        return -1
    if diff > 0:
        return 1
    return 0


def lower_bound_index(sorted_keys, literal):
    """First index whose key compares >= literal, or None."""
    lo, hi = 0, len(sorted_keys)
    while lo < hi:
        mid = (lo + hi) // 2
        if compare_keys(sorted_keys[mid], literal) < 0:
            lo = mid + 1
        else:
            hi = mid
    return lo if lo < len(sorted_keys) else None


class ChainExhausted(Exception):
    """The clock chain has fewer than the three nodes the window walks."""


def clock_dispatch(slots, sentinel):
    """The 3-node +0x98 dispatch chain.

    The first slot is called when it differs from the sentinel,
    else the second on the same condition, else the third
    unconditionally. ``slots`` holds the three slot values.
    """
    if len(slots) < 3:
        raise ChainExhausted("clock chain has fewer than 3 nodes")
    if slots[0] != sentinel:
        return slots[0]
    if slots[1] != sentinel:
        return slots[1]
    return slots[2]


def unsigned_elapsed(clock, stamp):
    """(clock - stamp) modulo 2**64, as the window computes it."""
    return (clock - stamp) % USIZE


def format_secs(clock, stamp):
    """\"%f\" % (unsigned elapsed / 1,000,000.0)."""
    return "%f" % (unsigned_elapsed(clock, stamp) / 1000000.0)


def names_at(names, index):
    """The global map's at(): missing keys raise, as map::at does."""
    try:
        return names[index]
    except KeyError:
        raise KeyError("map::at") from None


def build_report(counters, names, target, clock_slots, sentinel, stamp):
    """Run the whole window: 9 counter entries plus db.uptime.

    ``counters`` is a list of exactly 9 unsigned values (outer+0x00
    .. outer+0x40); ``names`` maps 0..8 to name byte strings;
    ``target`` is the report map (dict, mutated in place);
    ``clock_slots`` holds the three +0x98 slot values and
    ``sentinel`` is the 0x5777bc8 cell's runtime value.
    Returns the mutated target.
    """
    if len(counters) != ENTRY_COUNT:
        raise ValueError("expected %d counters" % ENTRY_COUNT)
    for index in range(ENTRY_COUNT):
        name = names_at(names, index)
        target[name] = itoa(counters[index])
    target[UPTIME_KEY] = format_secs(
        clock_dispatch(clock_slots, sentinel), stamp)
    return target


def report_via_wrapper(counters, names, target, clock_slots, sentinel,
                       stamp):
    """The 0x5159950 wrapper: forward the args, return 1."""
    build_report(counters, names, target, clock_slots, sentinel, stamp)
    return 1
