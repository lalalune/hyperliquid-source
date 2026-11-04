"""Pure mathematical value reference, independent of native/source algorithms.

No I/O, captured-byte decoding, machine-state evaluation or project imports.
Inputs are actual physical (bytes20, u64) rows and an actual selected sequence.
The linear order statistic and unbounded sums deliberately differ from the
intended source binary search and stepwise saturating additions.
"""

U64_MAX = 18446744073709551615


def _word(value):
    return type(value) is int and 0 <= value <= U64_MAX


def _key(value):
    return type(value) is bytes and len(value) == 20


def observe(rows, head, live, selected):
    """Return ('bounds',), ('order',), or ('ok', selected_sum, total_sum, bit).

    Scalar/key type failures are outside this value API and raise ValueError.
    Bounds and ordering failures are the explicitly chosen safe host policies.
    Finite slices, stable values, and host resources are ordinary prerequisites.
    """
    if not _word(head) or not _word(live):
        raise ValueError("head/live outside scalar input domain")
    if any(not _key(key) or not _word(weight) for key, weight in rows):
        raise ValueError("row outside bytes20/u64 input domain")
    if any(not _key(key) for key in selected):
        raise ValueError("selected value outside bytes20 input domain")

    capacity = len(rows)
    if live > capacity:
        return ("bounds",)
    if capacity == 0:
        if head != 0 or live != 0:
            return ("bounds",)
    elif head >= capacity:
        return ("bounds",)

    # Python integers/modulo express the mathematical physical mapping.
    logical = [rows[(head + i) % capacity] for i in range(live)]
    keys = [key for key, _ in logical]
    if any(left > right for left, right in zip(keys, keys[1:])):
        return ("order",)

    seam = capacity - head if live > capacity - head else None
    contributions = []
    for query in selected:
        if seam is not None and keys[seam] == query:
            index = seam
        else:
            # Two complete linear counts define a rightmost-equal statistic;
            # this is neither the native midpoint loop nor a callback result.
            less = sum(key < query for key in keys)
            equal = sum(key == query for key in keys)
            index = less + equal - 1 if equal else None
        contributions.append(0 if index is None else logical[index][1])

    selected_sum = min(U64_MAX, sum(contributions))
    total_sum = min(U64_MAX, sum(weight for _, weight in logical))
    passes = int(2 * total_sum < 3 * selected_sum)
    return ("ok", selected_sum, total_sum, passes)
