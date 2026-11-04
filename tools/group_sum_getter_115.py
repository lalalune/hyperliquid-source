"""Python model of node #115's group-sum getter 0x5eeb670 and its
callee, the nested group sum 0x5f6abb0.

Implements the semantics pinned by
research/work-items/RE-001-group-sum-getter-115. The getter takes
(outer, out, obj): the outer object in rdi is IGNORED, out is the
rsi pointer (modelled as a one-element list), and the summed object
is the fourth argument in rcx. The getter stores one qword to *out
and returns 1 unconditionally: 0 when the object is null, otherwise
the group sum.

State shapes (all plain dicts, no binary layout):

- A sum object is::

    {
      "addr": int,            # the object's own base address
      "field10": {"addr": int, "field8c0": value},
                              # mirrors [obj + 0x10] and the qword
                              # at [obj + 0x10] + 0x8c0
      "vec_begin": int,       # value at obj + 0x100
      "vec_end": int,         # value at obj + 0x108
      "field70": int,         # value at obj + 0x70
      "inline_descs": [...],  # group descriptors for indices 0..7
      "vec_descs": [...],     # group descriptors for indices 8+
    }

  A group descriptor is ``(count, [items])`` where each item is
  ``{"field28": value}`` mirroring the qword at item + 0x28; the
  binary reads the descriptor's count from [desc] and its item base
  from [desc + 0x08], with item stride 80 bytes.

- The 5-argument callee 0x5f415c0 is NOT read; it is a
  caller-supplied callable receiving, in order, ([field10] + 0x8c0
  value, obj + 0x1040, [field10] + 0x40, item field28, obj + 0x1118),
  and its return is added to the running sum. The binary re-reads
  [obj + 0x10] for every item, so the model re-reads ``field10``
  per item too.

Model-side guards (not binary behavior, stated explicitly): the
binary has no null checks and would fault on a dangling pointer,
and a negative group total would loop rather than return; the
model raises ValueError for a negative total instead of looping.
Descriptor lists shorter than the addressed index raise IndexError
naturally, mirroring an out-of-range read the binary would fault
on. Sums use plain Python integers (the binary wraps at 64 bits;
tests stay inside the range where wrapping is invisible).
"""

MASK64 = (1 << 64) - 1


def group_sum(obj, callee):
    """Group sum 0x5f6abb0: sum of callee returns over all groups.

    total = arithmetic_shift_right(vec_end - vec_begin, 4) + field70.
    A total of 0 returns 0 at once. Group i uses inline_descs[i]
    for i <= 7 and vec_descs[i - 8] for i > 7; a group whose count
    is 0 contributes nothing. Within a group, item j contributes
    callee(field10.field8c0, obj.addr + 0x1040,
    field10.addr + 0x40, item.field28, obj.addr + 0x1118).
    """
    total = ((obj["vec_end"] - obj["vec_begin"]) >> 4) + obj["field70"]
    if total < 0:
        raise ValueError("negative group total %d" % total)
    if total == 0:
        return 0
    result = 0
    for i in range(total):
        if i <= 7:
            count, items = obj["inline_descs"][i]
        else:
            count, items = obj["vec_descs"][i - 8]
        for j in range(count):
            field10 = obj["field10"]
            result += callee(
                field10["field8c0"],
                obj["addr"] + 0x1040,
                field10["addr"] + 0x40,
                items[j]["field28"],
                obj["addr"] + 0x1118,
            )
    return result


def getter(outer, out, obj, callee):
    """Getter 0x5eeb670: *out = 0 if obj is null else group_sum(obj).

    The outer argument is ignored entirely. Returns 1 always.
    """
    if obj is None:
        out[0] = 0
    else:
        out[0] = group_sum(obj, callee)
    return 1
