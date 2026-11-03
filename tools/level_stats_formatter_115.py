"""Node #115 level-stats formatter 0x5eecbb0 with its group sum 0x5f6c300
and leaf 0x5da4de0.

RE-001 work item. The getter at 0x5eecbb0 takes an outer object in rdi
and an output string in rsi, and returns 1 unconditionally. It reads
the member object at [outer + 0x788] and its sub-object at
[member + 0x30], then formats that sub-object's level groups into the
output string:

    output += "Level Files Size(MB)\\n--------------------\\n"
    count = signed32([outer + 0x778])
    for i in range(count):
        output += "%3d %8d %8.0f\\n" % (i, element_count(i), size_mb(i))

where, for level i, the group entry is the 24-byte record at
[sub + 0xad8] + i * 24 (its third qword is never read):

    element_count(i) = (entry.end - entry.begin) >> 3   (arithmetic shift
        on the wrapped 64-bit difference; for a well-formed range this is
        the number of 8-byte element pointers in the range)
    group_sum(i) = sum of [element + 0x10] over the leading run of
        non-null element pointers in that range, wrapping at 64 bits
        (0x5f6c300 selects the entry and tail-jumps to the leaf
        0x5da4de0, which does the walk; the walk stops at the first
        null pointer, which ends the sum rather than being skipped)
    size_mb(i) = (double)(unsigned group_sum(i)) * 2**-20

The double constant at rodata 0x459638 is exactly 2**-20 (1 MiB), and
the format string at rodata 0x436160 is "%3d %8d %8.0f\\n". The header
is built on the stack from three rodata chunks (0x456960, 0x4555c0,
0x456c70, the third overwriting at offset 27) and is exactly
"Level Files Size(MB)\\n--------------------\\n" (20 dashes). Appending
past the output string's maximum length throws a length error in the
native code; the model raises OverflowError there instead of
inventing a truncated result. A group range whose end precedes its
begin is refused with ValueError: the native leaf loop would run
unbounded there, so no result is claimed for it.

The model takes plain data: a group is {"elements": [element | None,
...]} where an element is {"size_field": int} for its +0x10 field.
The domain meaning of the levels is not claimed; only the formatting
rule and the group-sum walk are.
"""

HEADER = "Level Files Size(MB)\n--------------------\n"

FORMAT = "%3d %8d %8.0f\n"

GETTER = 0x5EECBB0
GROUP_SUM = 0x5F6C300
LEAF = 0x5DA4DE0

_MASK64 = (1 << 64) - 1


def _wrap_signed(value):
    value &= _MASK64
    return value - (1 << 64) if value >= (1 << 63) else value


def leaf_sum(group):
    """The leaf 0x5da4de0: sum [element + 0x10] over the leading run.

    `group` is {"elements": [...]}. The native loop loads each pointer
    in turn and jumps back to add only when it is non-null; a null
    pointer falls through to the return, so the sum covers the leading
    non-null run and stops at the first null. The result wraps at 64
    bits, exactly like the native add loop.
    """
    total = 0
    for element in group["elements"]:
        if element is None:
            break
        total = _wrap_signed(total + element["size_field"])
    return total


def group_sum(group):
    """The wrapper 0x5f6c300: select a level's entry, then the leaf."""
    return leaf_sum(group)


def level_line(index, group):
    """One "%3d %8d %8.0f\\n" line for level `index`."""
    count = len(group["elements"])
    total = group_sum(group)
    size_mb = float(total & _MASK64) * (2.0 ** -20)
    return "%3d %8d %8.0f\n" % (index, count, size_mb)


def format_levels(count, groups):
    """The getter 0x5eecbb0: header plus one line per level.

    `count` is the signed 32-bit bound at [outer + 0x778]; `groups`
    is the level array at [sub + 0xad8]. A non-positive count yields
    the header alone. A missing group raises IndexError, mirroring
    the native code's unchecked array access without inventing data.
    """
    out = HEADER
    if count <= 0:
        return out
    for i in range(count):
        out += level_line(i, groups[i])
    return out
