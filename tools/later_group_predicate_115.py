"""Model of node #115 later-group predicate 0x5f6d600 (RE-001).

The predicate decides, for one element of one group, whether any later
group decides against it: it returns 1 when a later group does (the
filter pass 0x5f6d700 then skips the element) and 0 otherwise.

Inputs mirror the native registers: obj is represented by its group
count (signed 32-bit value at obj+0x10) and its group-entry array
(pointer at obj+0xa98; entry i is a (begin, end) pair of unsigned
64-bit values, the third qword never read). The selector 0x5f6c2a0
and its dispatch callee are not modelled here: the caller supplies
selector results through a callable taking a later group index and
returning 0 or 1, exactly the oracle the native loop consults.
"""

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def _s32(value):
    value &= MASK32
    return value - (1 << 32) if value >= (1 << 31) else value


def _s64(value):
    value &= MASK64
    return value - (1 << 64) if value >= (1 << 63) else value


class LaterGroupPredicate:
    def __init__(self, count, entries, group, elem_index, selector):
        """count: signed 32-bit group count; entries: list of (begin, end);
        group: the element's group index (ecx); elem_index: r8d, read only
        when group == 0; selector: callable(later_group_index) -> 0/1."""
        if not isinstance(group, int) or group < 0:
            raise ValueError("group must be a non-negative index")
        self.count = _s32(count)
        self.entries = list(entries)
        self.group = group
        self.elem_index = elem_index & MASK32
        self.selector = selector

    def _entry(self, index):
        if index < 0 or index >= len(self.entries):
            raise ValueError("entry index out of range: %d" % index)
        return self.entries[index]

    def run(self):
        if self.group == 0:
            begin, end = self._entry(0)
            diff = _s64(end - begin)
            last = ((_s64(diff >> 3) & MASK32) - 1) & MASK32
            if self.elem_index != last:
                return 1
            if self.count <= 1:
                return 0
            for index in range(1, self.count):
                begin, end = self._entry(index)
                if begin != end:
                    return 1
            return 0
        nxt = _s32(self.group + 1)
        while self.count > nxt:
            begin, end = self._entry(nxt)
            if begin != end:
                if self.selector(nxt):
                    return 1
            nxt = _s32(nxt + 1)
        return 0
