#!/usr/bin/env python3
"""Model for node #94's level-index sum formatter 0x514dce0 (RE-001).

The window function takes an outer object, a destination string and a
(pointer, length) view holding a decimal index. It returns 1 and sets
the destination to the decimal sum of the +0x10 fields of all records,
across all levels, whose +0xb7 byte equals the parsed index; it
returns 0 with the destination unchanged when the view is not exactly
one decimal index (empty view, non-digit first character, parser
overflow, or trailing characters). Unlike the level-ratio formatter,
there is no index-range gate: an index matching nothing still
returns 1 with "0".

The container layout pinned by the packet: [outer+0x788] ->
sub-object; [sub-object+0x30] = container; the container's level
count is the signed int32 at +0x50 (count <= 0 skips the loop) and
the level array pointer is at +0xad8, with 0x18-byte level entries
(begin +0x0, end +0x8) holding spans of 8-byte record pointers.

Inputs here are abstracted: levels is a list of levels, each a list
of (match_byte, summed_value) record pairs. The sum is a wrapping
int64 sum. Decimal formatting is pinned only for non-negative sums:
the formatter callee's entry thresholds are unsigned compares, so a
bit-63-set (negative) sum is an explicit unknown and raises
ValueError rather than being silently formatted. Stdlib only.
"""

UINT64_MAX = 2 ** 64 - 1
INT64_MIN = -(2 ** 63)
INT64_MAX = 2 ** 63 - 1
_OVERFLOW_LIMIT = 0x1999999999999999


def parse_decimal_view(view):
    """The 0x54307c0 parser plus the caller's full-consumption gate.

    Returns (ok, value, remaining). ok is False when the parser
    returns 0 (empty view or a non-digit first character, or
    overflow) or when trailing characters remain. On overflow the
    value is None, matching the bytes (the output slot is not
    written); on a parse failure with no digit consumed the value
    is 0.
    """
    if len(view) == 0:
        return (False, 0, view)
    value = 0
    consumed = 0
    for byte in view:
        if not 48 <= byte <= 57:
            break
        digit = byte - 48
        if value > _OVERFLOW_LIMIT or (
                value == _OVERFLOW_LIMIT and digit > 5):
            return (False, None, view[consumed:])
        value = value * 10 + digit
        consumed += 1
    if consumed == 0:
        return (False, 0, view)
    remaining = view[consumed:]
    if remaining:
        return (False, value, remaining)
    return (True, value, b"")


def _wrap_int64(value):
    value &= UINT64_MAX
    return value - 2 ** 64 if value >= 2 ** 63 else value


def level_index_sum(levels, index):
    """The window's sum loop over all levels' record spans."""
    total = 0
    for level in levels:
        for match_byte, summed in level:
            if match_byte == index:
                total = _wrap_int64(total + summed)
    return total


def format_level_index_sum(levels, view):
    """End-to-end window behavior.

    levels is the level array (a list of levels); view is the raw
    view bytes. Returns (return_code, destination_or_None) where
    None means the destination is left unchanged (the failure
    paths), and a string on success.
    """
    ok, index, _remaining = parse_decimal_view(view)
    if not ok:
        return (0, None)
    total = level_index_sum(levels, index)
    if total < 0:
        raise ValueError(
            "negative sum formatting is unmodelled: the formatter "
            "callee's sign treatment of a bit-63-set sum is unknown")
    return (1, "%d" % total)
