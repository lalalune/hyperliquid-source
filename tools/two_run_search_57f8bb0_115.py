"""Model of the node #115 two-run search routine at 0x57f8bb0.

The routine is a binary search over 40-byte records keyed by
each record's first qword, where the records form one logical
sorted sequence stored in two physical runs of one buffer:

  * run A: physical indices [start, start + skip)
  * run B: physical indices [0, len1)

with, in u64 arithmetic,

  start = f2 - f0   if f2 >= f0   else   f2
  skip  = f0 - start
  len1  = f3 - skip

The four descriptor words are read from the caller's struct at
+0x0 (f0), +0x8 (buffer base), +0x10 (f2) and +0x18 (f3); the
key is the qword pointed to by the second argument.

Search order is exact:

  * f3 == 0: return (1, 0) without reading any record.
  * f3 <= skip (run B empty, or the wrapped length borrows):
    search run A only, with length f3, and return its local
    result unchanged.
  * Otherwise compare the key against record 0 (the first
    record of run B):
      - equal: return (0, skip);
      - record 0 greater: the key can only belong to run A;
        if skip == 0 return (1, 0), else search run A with
        length skip and return its local result unchanged;
      - record 0 smaller: binary-search run B and return
        (flag, skip + local index).

Each segment search is the binary's own loop, transcribed
operation for operation, and returns flag 0 for an exact match
and flag 1 otherwise; the index is the match position or the
insertion position that keeps the logical sequence sorted.
The pair (flag, index) is returned in (rax, rdx).

The model raises ValueError for inputs outside the u64 word
range; on inputs whose field arithmetic would make the binary
read outside the supplied record list it raises IndexError
from the list access, mirroring that such inputs are outside
the modelled domain. What f0/f2/f3 denote in the caller's
terms is not modelled; only the arithmetic above is.
"""

MASK = (1 << 64) - 1


def _check_word(name, value):
    if not isinstance(value, int) or isinstance(value, bool) \
            or value < 0 or value > MASK:
        raise ValueError("%s is not a u64 word: %r" % (name, value))


def _search_from_zero(keys, length, key):
    """Search physical indices [0, length); the phase-1 loop."""
    lo = 0
    size = length
    if size != 1:
        while True:
            saved = lo
            half = size >> 1
            lo = (lo + half) & MASK
            if keys[lo] > key:
                lo = saved
            size -= half
            if size <= 1:
                break
    elem = keys[lo]
    if elem == key:
        return (0, lo)
    if elem < key:
        lo = (lo + 1) & MASK
    return (1, lo)


def _search_from_base(keys, base, length, key):
    """Search physical indices [base, base + length); the
    phase-2 loop; the returned index is local to the run."""
    lo = 0
    size = length
    if size != 1:
        while True:
            saved = lo
            half = size >> 1
            lo = (lo + half) & MASK
            if keys[base + lo] > key:
                lo = saved
            size -= half
            if size <= 1:
                break
    elem = keys[base + lo]
    if elem == key:
        return (0, lo)
    if elem < key:
        lo = (lo + 1) & MASK
    return (1, lo)


def two_run_search(f0, f2, f3, keys, key):
    """Return (flag, index) for the descriptor words f0/f2/f3,
    the physical record keys (first qword of each 40-byte
    record, by physical index) and the search key."""
    _check_word("f0", f0)
    _check_word("f2", f2)
    _check_word("f3", f3)
    _check_word("key", key)
    if f3 == 0:
        return (1, 0)
    start = (f2 - f0) & MASK if f2 >= f0 else f2
    skip = (f0 - start) & MASK
    if f3 <= skip:
        return _search_from_base(keys, start, f3, key)
    len1 = f3 - skip
    head = keys[0]
    if head == key:
        return (0, skip)
    if head > key:
        if skip == 0:
            return (1, 0)
        return _search_from_base(keys, start, skip, key)
    flag, index = _search_from_zero(keys, len1, key)
    return (flag, (skip + index) & MASK)
