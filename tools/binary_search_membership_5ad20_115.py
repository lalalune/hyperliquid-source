"""Model of node #115 routine 0x5d5ad20: binary-search membership test
over a sorted array of 0x20-byte records.

Representation: a record is a pair (buffer, length), mirroring the
routine's record layout: data pointer at +0x00, length at +0x08.
Only the first ``length`` bytes of the buffer take part in a
comparison; the remaining 16 bytes of each 0x20-byte record are
never read by the routine and are not modelled. A range is a list
of records in the order the routine walks them; the search is a
lower-bound search, so it is meaningful on a range ordered by the
same record comparison (an assumption the routine itself does not
check).

Comparison, exactly as the routine pins it: compare the shorter
of the two effective byte strings first (the routine's memcmp
over min(len_a, len_b)); on a tie, compare lengths, with the
difference clamped to the int32 range the routine enforces
(loop: a difference at or above 2**31 counts as non-negative,
below -2**31 counts as negative; tail: a difference above
INT_MAX counts as positive, below INT_MIN counts as negative).

``present(records, key)`` returns True exactly when the range
holds a record equal to the key: the loop finds the first record
not less than the key, and the tail check returns True exactly
when the key is not less than that candidate.
"""

INT_MAX = 0x7FFFFFFF
INT_MIN = -0x80000000


def _byte_sign(a, b):
    """Sign of the byte-string comparison over the shared prefix."""
    n = min(len(a), len(b))
    x, y = a[:n], b[:n]
    if x < y:
        return -1
    if x > y:
        return 1
    return 0


def _effective(record):
    buffer, length = record
    return bytes(buffer)[:length]


def record_less(elem, key):
    """True when elem < key under the routine's loop comparison."""
    a, b = _effective(elem), _effective(key)
    sign = _byte_sign(a, b)
    if sign != 0:
        return sign < 0
    diff = len(a) - len(b)
    if diff >= 0x80000000:
        return False
    return diff < 0


def key_less_candidate(key, cand):
    """True when key < cand under the routine's tail comparison."""
    a, b = _effective(key), _effective(cand)
    sign = _byte_sign(a, b)
    if sign != 0:
        return sign < 0
    diff = len(a) - len(b)
    if diff > INT_MAX:
        return False
    if diff < INT_MIN:
        return True
    return diff < 0


def lower_bound(records, key):
    """Index of the first record not less than key (len if none)."""
    first, count = 0, len(records)
    while count > 0:
        step = count // 2
        mid = first + step
        if record_less(records[mid], key):
            first = mid + 1
            count = count - step - 1
        else:
            count = step
    return first


def present(records, key):
    """True when the range holds a record equal to key."""
    index = lower_bound(records, key)
    if index >= len(records):
        return False
    return not key_less_candidate(key, records[index])
