"""Node #115 twin entry-sum getters 0x5eec290 / 0x5eec300 with leaf 0x5dd3570.

RE-001 work item. Both getters walk the same 16-byte entry range of the
sub-object at [outer + 0x788] + 0x30:

    begin = [sub + 0xb18], end = [sub + 0xb20]

For every entry, E = [entry] (first qword) and F = [E] (first qword of E).
The leaf returns [F + 0x10] + 62 (64-bit wrapping).

Getter A (0x5eec290) sums the leaf result per entry.
Getter B (0x5eec300) calls the same leaf per entry, DISCARDS its return,
and instead sums [E + 0x50] per entry. The discarded call is real: it is
present in the disassembly of B, and B's result does not depend on the
leaf field at all. Both getters store the total into *out and return 1
unconditionally; neither checks any pointer for null, and an empty range
sums to 0. All arithmetic wraps modulo 2**64.

The model takes plain data: an entry is a dict {"f10": int, "e50": int}
where f10 stands for [F + 0x10] and e50 for [E + 0x50]. Missing keys raise
KeyError, mirroring the native code's unchecked dereferences.
"""

MASK = (1 << 64) - 1


def leaf_value(f10):
    """Leaf 0x5dd3570: [F + 0x10] + 62, 64-bit wrapping."""
    return (f10 + 62) & MASK


def getter_a(entries):
    """Getter 0x5eec290: sum of leaf results over the entry range."""
    total = 0
    for entry in entries:
        total = (total + leaf_value(entry["f10"])) & MASK
    return total


def getter_b(entries):
    """Getter 0x5eec300: sum of [E + 0x50]; the leaf call's result is discarded."""
    total = 0
    for entry in entries:
        leaf_value(entry["f10"])  # called, return discarded, exactly as in the binary
        total = (total + entry["e50"]) & MASK
    return total


def run_getter(getter, outer):
    """(outer, out) shape: outer["member788"]["sub30"]["entries"]; returns (1, total)."""
    entries = outer["member788"]["sub30"]["entries"]
    return 1, getter(entries)


if __name__ == "__main__":
    assert run_getter(getter_a, {"member788": {"sub30": {"entries": []}}}) == (1, 0)
    assert run_getter(getter_b, {"member788": {"sub30": {"entries": []}}}) == (1, 0)
    print("twin_entry_sum_getters_115 smoke OK")
