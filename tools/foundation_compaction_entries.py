"""Model for node #94 0x51599e0 (RE-001-compaction-entries-94).

The window builds compaction report entries into a destination map.
A collector callee (0x5151970) first fills a group tree from the
outer object's state; the window then walks every group, and for
every entry of the group it resolves the entry's integer key to a
name through a global int-to-string map, and stores the entry's
double value, rendered with "%f", under the segment key
``compaction.<group>.<name>`` in the destination map. A thin
wrapper (0x515a800) forwards the arguments and returns 1, and an
epilogue callee (0x5155710) runs over (outer, destination) after
the build; neither the collector's grouping rule nor the
epilogue's follow-up writes are modelled here, so the model takes
the groups as parameters.

The expectations are transcribed from the window's disassembly
(see research/work-items/RE-001-compaction-entries-94/): the
signed int32 digit ladder and digit-pair fill of the inlined
itoa, the "L" prefix inserted at the front of the key text, the
"Sum" text for the -1 group, the global map's at() lookup, the
saturating string comparison of the destination-map walk, and
the insert-or-replace value store.
"""

INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1
SEGMENT_PREFIX = b"compaction."
SEGMENT_DOT = b"."
SUM_TEXT = b"Sum"
KEY_PREFIX = b"L"

PAIR_TABLE = ["%02d" % i for i in range(100)]


def digit_count_magnitude(magnitude):
    """Digit count of a non-negative magnitude, as the ladder gives.

    Thresholds: 9 / 99 / 999 / 9999 / 99999 / 999999 / 9999999 /
    99999999 / 999999999, then 10 digits above that.
    """
    if magnitude <= 9:
        return 1
    if magnitude <= 99:
        return 2
    if magnitude <= 999:
        return 3
    if magnitude <= 9999:
        return 4
    if magnitude <= 99999:
        return 5
    if magnitude <= 999999:
        return 6
    if magnitude <= 9999999:
        return 7
    if magnitude <= 99999999:
        return 8
    if magnitude <= 999999999:
        return 9
    return 10


def itoa_int32(value):
    """Signed int32 decimal rendering via the window's pair fill.

    The window takes the absolute value (INT32_MIN's negation
    wraps, and the divide loop then runs on the zero-extended
    magnitude 2**31), writes digit pairs from the end per
    divide-by-100 step, and leaves the '-' fill char at the front
    for negatives. The result is exactly str(value) for every
    int32 input, including INT32_MIN.
    """
    if value < INT32_MIN or value > INT32_MAX:
        raise ValueError("expected an int32 value")
    magnitude = value if value >= 0 else (1 << 31 if value == INT32_MIN else -value)
    count = digit_count_magnitude(magnitude)
    if count == 1:
        digits = chr(ord("0") + magnitude)
    elif count == 2:
        digits = PAIR_TABLE[magnitude]
    else:
        buf = [""] * count
        pos = count - 1
        current = magnitude
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
        digits = "".join(buf)
    if value < 0:
        return "-" + digits
    return digits


def group_key_text(value):
    """The group key text: "Sum" for -1, else "L" + decimal text.

    The "L" is inserted at position 0 of the itoa string by a
    string replace of length 0 at position 0, so for negatives it
    lands in front of the '-'.
    """
    if value == -1:
        return SUM_TEXT
    return KEY_PREFIX + itoa_int32(value).encode()


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


def names_at(names, key):
    """The global map's at(): missing keys raise, as map::at does."""
    try:
        return names[key]
    except KeyError:
        raise KeyError("map::at") from None


def segment_key(group_value, name):
    """compaction.<group text>.<name>, exactly as the window builds it."""
    return SEGMENT_PREFIX + group_key_text(group_value) + SEGMENT_DOT + name


def build_entries(groups, names, target):
    """Run the whole window over groups into the destination map.

    ``groups`` is a list of (group_value, entries) pairs, where
    each entry is (entry_key, entry_value); ``names`` maps integer
    entry keys to name byte strings; ``target`` is the destination
    map (dict, mutated in place). A segment key already present is
    overwritten with the new "%f" value, as the window's found
    path move-assigns into the existing node's value string.
    Returns the mutated target.
    """
    for group_value, entries in groups:
        key_text = group_key_text(group_value)
        for entry_key, entry_value in entries:
            name = names_at(names, entry_key)
            segment = SEGMENT_PREFIX + key_text + SEGMENT_DOT + name
            target[segment] = "%f" % entry_value
    return target


def build_via_wrapper(groups, names, target):
    """The 0x515a800 wrapper: forward the args, return 1."""
    build_entries(groups, names, target)
    return 1
