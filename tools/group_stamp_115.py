"""Model of node #115 group-stamp behavior (RE-001, work item
RE-001-group-stamp-115).

Windows (digest-verified node #115 binary, see the work-item packet):
  predicate 0x5f6c4e0 -- any element stamp zero?
  maximum   0x5f6c540 -- largest element stamp (unsigned)
  caller    0x5f6c5a0 -- claim the arg2+0x9e0 slot, stamp, or restore

Layout pinned by the disassembly:
  obj+0x10   signed 32-bit group count
  obj+0xa98  24-byte group entries: begin qword, end qword, third
             qword never read; elements are 8-byte pointers in
             [begin, end)
  element+0xd0  the stamp field
  arg2+0x9e0   the counter slot (qword)
  arg2+0x4fb   flag byte selecting the first log call
  obj+0xfd4    written to 1 only on the stamp path

The log callee 0x5fceda0 is recorded in the packet but not modelled:
it does not change the groups, the slot, or the flag.
"""

MASK = (1 << 64) - 1


def _u64(value):
    return value & MASK


def has_zero_stamp(groups, count):
    """Predicate 0x5f6c4e0: 1 when any element in groups[0:count]
    has stamp 0, else 0. A non-positive count returns 0 without
    reading any group."""
    if count <= 0:
        return False
    for group in groups[:count]:
        for stamp in group:
            if stamp == 0:
                return True
    return False


def max_stamp(groups, count):
    """Maximum 0x5f6c540: the largest element stamp over
    groups[0:count] under an unsigned compare, starting from 0,
    so an empty selection yields 0."""
    result = 0
    if count <= 0:
        return 0
    for group in groups[:count]:
        for stamp in group:
            stamp = _u64(stamp)
            if result < stamp:
                result = stamp
    return result


def apply_group_stamp(count, groups, slot, flag_byte):
    """Caller 0x5f6c5a0, stated literally.

    Entry writes 1 to the slot (the previous value is discarded).
    When the flag byte is nonzero the slot is first incremented
    once (lock xadd) and a log call is made. The predicate then
    decides:

    stamp path -- groups count-1 down to 1, in that order: each
      non-empty group takes one fresh slot value (lock xadd) and
      stamps every element of the group with it; then group 0 is
      stamped per element, walking its elements in reverse order,
      one fresh slot value each. Afterwards a second log call is
      made and obj+0xfd4 is written to 1. The slot is left at its
      last incremented value.
    max path -- no element has stamp 0: the slot is written with
      max(max_stamp + 1, current slot) under an unsigned compare
      (max_stamp + 1 wraps at 64 bits). obj+0xfd4 is untouched.

    Returns a dict with path ("stamp" or "max"), the final slot,
    the stamped groups, and whether obj+0xfd4 was written.
    The native %rax on return (log callee return on the stamp
    path, previous slot value on the max path) is not a pinned
    part of this contract.
    """
    if count < 0:
        raise ValueError("negative group count")
    if len(groups) < count:
        raise ValueError("fewer groups than count")
    stamps = [[_u64(s) for s in group] for group in groups]
    slot = 1  # entry xchg writes 1 to the slot
    if flag_byte != 0:
        slot = _u64(slot + 1)  # lock xadd before the first log call
    if has_zero_stamp(stamps, count):
        for gi in range(count - 1, 0, -1):
            if stamps[gi]:
                value = slot
                slot = _u64(slot + 1)
                stamps[gi] = [value] * len(stamps[gi])
        if count >= 1:
            group0 = stamps[0]
            for ei in range(len(group0) - 1, -1, -1):
                value = slot
                slot = _u64(slot + 1)
                group0[ei] = value
        return {"path": "stamp", "slot": slot, "groups": stamps,
                "fd4_written": True}
    computed = _u64(max_stamp(stamps, count) + 1)
    if computed < slot:
        computed = slot
    return {"path": "max", "slot": computed, "groups": stamps,
            "fd4_written": False}
