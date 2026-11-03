"""Node #115 downward group scan 0x5d52bb0 with its index leaf 0x5f6c740,
group sum 0x5f6c300 and leaf 0x5da4de0.

RE-001 work item. The scanner at 0x5d52bb0 takes an outer object in rdi,
an object in rsi and a 32-bit count in ecx, and returns a 32-bit index.
It reads the sub-object at [obj + 0x30] and that sub-object's level
groups (24-byte entries at [sub + 0xad8]) plus the index array whose
base is [sub + 0x58]:

    stub(outer + 0x700, obj)          # 0x60d5390: endbr64; ret, no effect
    if n - 1 <= 0 (signed 32-bit):    # n <= 1
        return n
    i = n - 1
    loop:
        count_i = (entry_i.end - entry_i.begin) >> 3   (arithmetic shift
            on the wrapped 64-bit difference; for a well-formed range
            this is the number of 8-byte pointers in group i's range)
        the native test is `test %eax,%eax` on the low 32 bits, so the
        model tests signed32(count_i) > 0, which coincides with the
        range length for every list-representable range
        if count_i > 0 (32-bit test):
            return i + 1              # fall-through to the epilogue
        a = index_array[i]            # 0x5f6c740: [[sub + 0x58] + i * 8],
                                      # i sign-extended from 32 bits
        b = group_sum(n)              # 0x5f6c300 selects entry n and
                                      # tail-jumps to the leaf 0x5da4de0,
                                      # which sums [element + 0x10] over
                                      # the leading run of non-null
                                      # element pointers in group n's
                                      # range, wrapping at 64 bits, and
                                      # stops at the first null pointer
        if a < b (unsigned):          # cmp %rax,%r15; jb: a below b
            return i + 1
        i -= 1
        return 1 if i == 0 else continue

Note the asymmetry the native code actually has: the count test uses
group i's full range length, while the comparison value b always comes
from group n (the original count), not from group i. A group whose
range holds a single null pointer has count 1, so it counts as
non-empty here even though its leaf sum would be 0. The domain meaning
of the groups and of the index array is not claimed; only the scan
rule and the callee walks are.

The model takes plain data: a group is {"pointers": [element | None,
...]} where an element is {"size_field": int} for its +0x10 field, and
the range length is len(pointers). A group range whose end precedes
its begin cannot be represented by a pointer list and is refused with
ValueError, as in the earlier level items: the native leaf loop would
run unbounded there, so no result is claimed for it. A missing group
or index entry raises IndexError, mirroring the native code's
unchecked array access without inventing data.
"""

SCANNER = 0x5D52BB0
STUB = 0x60D5390
INDEX_LEAF = 0x5F6C740
GROUP_SUM = 0x5F6C300
LEAF = 0x5DA4DE0

_MASK64 = (1 << 64) - 1


def _wrap_signed(value):
    value &= _MASK64
    return value - (1 << 64) if value >= (1 << 63) else value


def _signed32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >= (1 << 31) else value


def index_leaf(index_array, i):
    """The leaf 0x5f6c740: [[sub + 0x58] + i * 8], i sign-extended."""
    return index_array[i]


def leaf_sum(group):
    """The leaf 0x5da4de0: sum [element + 0x10] over the leading run.

    `group` is {"pointers": [...]}. The native loop loads each pointer
    in turn and adds only when it is non-null; a null pointer falls
    through to the return, so the sum covers the leading non-null run
    and stops at the first null. The result wraps at 64 bits.
    """
    total = 0
    for element in group["pointers"]:
        if element is None:
            break
        total = _wrap_signed(total + element["size_field"])
    return total


def group_sum(groups, n):
    """The wrapper 0x5f6c300: select entry n, then the leaf."""
    return leaf_sum(groups[n])


def downward_scan(n, groups, index_array):
    """The scanner 0x5d52bb0.

    `n` is the 32-bit count in ecx; `groups` is the level array at
    [sub + 0xad8]; `index_array` is the array at [sub + 0x58]. The
    opening stub call (0x60d5390) is endbr64; ret and has no observable
    effect, so it contributes nothing to the result.
    """
    n = _signed32(n)
    if _signed32(n - 1) <= 0:
        return n
    i = _signed32(n - 1)
    while True:
        group = groups[i]
        # Native: sar $0x3 then `test %eax,%eax; jle` — the fall-through
        # (count > 0) goes straight to the epilogue returning i + 1.
        if _signed32(len(group["pointers"])) > 0:
            return _signed32(i + 1)
        a = index_leaf(index_array, i)
        b = group_sum(groups, n)
        # Native: cmp %rax,%r15; jb — jump (return i + 1) when a < b
        # unsigned, where r15 = a (index value) and rax = b (group sum).
        if (a & _MASK64) < (b & _MASK64):
            return _signed32(i + 1)
        i = _signed32(i - 1)
        if i == 0:
            return 1
