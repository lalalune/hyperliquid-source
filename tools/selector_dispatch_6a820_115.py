"""Model of node #115 selector dispatch 0x5f6a820 (RE-001).

The dispatch is the callee the index selector 0x5f6c2a0 tail-jumps to
(the selector is pinned by the RE-001 later-group predicate item; this
item pins the dispatch body itself). It answers, for one level-files
brief and one user-key range, whether any file in the brief overlaps
the range: 1 means some file overlaps, 0 means none does (one arm-B
sub-case returns the flag itself, see below).

Native arguments, mirrored here:
  flag     -- esi: 0 selects the linear-scan arm; any nonzero value
              selects the find arm.
  count    -- the qword at brief+0 (re-read at every loop bound check
              in the native code; the model treats it as stable across
              one call, as the sibling models do).
  entries  -- the file array at brief+8; entry i is 80 bytes. Only two
              key fields are read, each a (data, size) pair: key A at
              entry+0x30/+0x38 and key B at entry+0x40/+0x48. A key's
              compared form is the user slice (data, size - 8) with
              wrapping 64-bit subtraction.
  smallest -- rcx: pointer to the range-start slice (data, length),
              or None for a null pointer.
  largest  -- r8: pointer to the range-end slice (data, length),
              or None for a null pointer.
  compare  -- oracle(a, b) -> int for two slice values (data, length).
              The native code reaches one of two callees (a fast route
              through the sub-object at comparator+0x20 when the user
              comparator's vtable slot +0xd0 holds the adapter thunk
              0x5d48410, else that slot itself with arguments
              (comparator, a, 1, b, 1)); both compute the same
              comparison, so the model takes the result as one oracle
              input, exactly the stance the sibling items take for
              their callees.
  find     -- oracle(built) -> int, used only on the find arm with a
              non-null range start. built is the exact byte string the
              native key builder produces (see _build); the returned
              value is taken at 32 bits and zero-extended, as the
              native code does.

Raises LengthError when the key builder's capacity guard trips
(a slice length above 0x3fffffffffffffff minus the current size).
"""

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1

FOOTER_PACKED = (-8) & MASK64   # qword the caller stores at record+0x10
FOOTER_TAG = 0x16               # byte the caller loads from rodata 0x9702ab
STRING_MAX = 0x3FFFFFFFFFFFFFFF  # the builder's capacity constant


class LengthError(Exception):
    """The key builder's length guard tripped (native: length_error)."""


def user_slice(key):
    """(data, size) entry key -> compared slice (data, size - 8 wrapping)."""
    data, size = key
    return (data, (size - 8) & MASK64)


def _build(smallest):
    data, length = smallest
    if length > STRING_MAX:
        raise LengthError("slice length above builder capacity")
    if length > len(data):
        raise ValueError("slice length exceeds the supplied data")
    built = data[:length]
    footer = ((FOOTER_PACKED << 8) | FOOTER_TAG) & MASK64
    if 8 > STRING_MAX - len(built):
        raise LengthError("footer above builder capacity")
    return built + footer.to_bytes(8, "little")


class SelectorDispatch:
    def __init__(self, flag, count, entries, smallest, largest,
                 compare, find):
        """flag: esi (0 or nonzero); count: brief+0 qword; entries: list
        of ((a_data, a_size), (b_data, b_size)); smallest/largest:
        (data, length) slice values or None; compare: oracle(a, b)->int;
        find: oracle(built_bytes)->int."""
        self.flag = flag & MASK32
        self.count = count
        self.entries = list(entries)
        self.smallest = smallest
        self.largest = largest
        self.compare = compare
        self.find = find

    def _entry(self, index):
        if index < 0 or index >= len(self.entries):
            raise ValueError("entry index out of range: %d" % index)
        return self.entries[index]

    def _scan_arm(self):
        # flag == 0; count > 0 already established by run().
        if self.smallest is None:
            return self._null_start_arm()
        index = 0
        while True:
            key_a, key_b = self._entry(index)
            if self.compare(self.smallest, user_slice(key_b)) <= 0:
                if self.largest is None:
                    return 1
                if self.compare(self.largest, user_slice(key_a)) >= 0:
                    return 1
            index += 1
            if index >= self.count:
                return 0

    def _null_start_arm(self):
        # flag == 0, count > 0, smallest is null.
        if self.largest is None:
            return 1
        index = 0
        while True:
            key_a, _key_b = self._entry(index)
            if self.compare(self.largest, user_slice(key_a)) >= 0:
                return 1
            index += 1
            if index >= self.count:
                return 0

    def _find_arm(self):
        if self.smallest is None:
            index = 0
        else:
            built = _build(self.smallest)
            index = self.find(built) & MASK32
        if index >= self.count:
            return 0
        if self.largest is None:
            return self.flag
        key_a, _key_b = self._entry(index)
        result = self.compare(self.largest, user_slice(key_a))
        return 1 if result >= 0 else 0

    def run(self):
        if self.flag != 0:
            return self._find_arm()
        if self.count == 0:
            return 0
        return self._scan_arm()
