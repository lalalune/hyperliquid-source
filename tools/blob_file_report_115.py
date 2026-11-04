"""Node #115 blob-file report getter 0x5ef0670 with leaf 0x5dd3570.

RE-001 work item. The getter walks the same 16-byte entry range of the
sub-object at [outer + 0x788] + 0x30 that the twin entry-sum getters of
#2307 walk:

    begin = [sub + 0xb18], end = [sub + 0xb20]

For every entry, E = [entry] (first qword) and F = [E] (first qword of E).
The leaf at 0x5dd3570 returns [F + 0x10] + 62 (64-bit wrapping).

Per entry the reporter accumulates two wrapping 64-bit sums:

    leaf_sum  += leaf(F)        (the "total size of blob files")
    other_sum += [E + 0x50]     (the "total size of garbage in blob files")

The entry's second qword is never read. The report count is
(end - begin) >> 4 (arithmetic shift; for a well-formed range this is the
entry count). The amplification ratio is an IEEE double:

    ratio = 0.0                                  if other_sum >= leaf_sum (unsigned)
    ratio = leaf_sum / (leaf_sum - other_sum)    otherwise

computed with the unsigned-to-double conversion the binary uses (the
cvtsi2sd + correction paths at 0x5ef06f2..0x5ef0714 and 0x5ef0980..0x5ef09c5),
so a difference with the high bit set still converts as unsigned.

The report is built with an ostringstream and assigned into *out; the
function returns 1 unconditionally and checks nothing for null. On the
normal (stream-good) path a trailing newline is appended via put('\\n')
at 0x5ef0970. The four label strings are rodata literals pinned in the
packet (0x43e666, 0x4437b1, 0x957348, 0x95d978). The ratio is formatted
with the default ostream double format (6 significant digits, %g style).
The remaining register/stack arguments of the getter's uniform signature
are saved but never read on the normal path; only (outer, out) matter.

The model takes plain data: an entry is a dict {"f10": int, "e50": int}
where f10 stands for [F + 0x10] and e50 for [E + 0x50]. Missing keys raise
KeyError, mirroring the native code's unchecked dereferences.
"""

MASK = (1 << 64) - 1


def leaf_value(f10):
    """Leaf 0x5dd3570: [F + 0x10] + 62, 64-bit wrapping."""
    return (f10 + 62) & MASK


def sums(entries):
    """(leaf_sum, other_sum) over the entry range, both wrapping."""
    leaf_sum = 0
    other_sum = 0
    for entry in entries:
        leaf_sum = (leaf_sum + leaf_value(entry["f10"])) & MASK
        other_sum = (other_sum + entry["e50"]) & MASK
    return leaf_sum, other_sum


def amplification(leaf_sum, other_sum):
    """The ratio arm: 0.0 when other_sum >= leaf_sum (unsigned), else the
    IEEE double leaf_sum / (leaf_sum - other_sum)."""
    if other_sum >= leaf_sum:
        return 0.0
    return float(leaf_sum) / float(leaf_sum - other_sum)


def format_double(value):
    """Default ostream double format: 6 significant digits, %g style."""
    return format(value, ".6g")


def report(entries):
    """The full report string the getter assigns into *out."""
    leaf_sum, other_sum = sums(entries)
    ratio = amplification(leaf_sum, other_sum)
    return (
        f"Number of blob files: {len(entries)}"
        f"\nTotal size of blob files: {leaf_sum}"
        f"\nTotal size of garbage in blob files: {other_sum}"
        f"\nBlob file space amplification: {format_double(ratio)}\n"
    )


def run_reporter(outer):
    """(outer, out) shape: outer["member788"]["sub30"]["entries"]; returns
    (1, report_string)."""
    entries = outer["member788"]["sub30"]["entries"]
    return 1, report(entries)


if __name__ == "__main__":
    assert run_reporter({"member788": {"sub30": {"entries": []}}}) == (
        1,
        "Number of blob files: 0\nTotal size of blob files: 0"
        "\nTotal size of garbage in blob files: 0"
        "\nBlob file space amplification: 0\n",
    )
    print("blob_file_report_115 smoke OK")
