"""Node #94 BlockCache report formatter (0x514f770): RE-001 work item.

Reconstructs the established semantics of the 0x514f770 window from
the digest-bound evidence packet
``research/work-items/RE-001-blockcache-report-94/``: a whole
snapshot report rendered into the destination string.

Snapshot layout (offsets from the snapshot object, 0x138 bytes total,
shared with the timed-snapshot packet):

    +0x00   capacity value (scaled by the helper, ratio denominator)
    +0x08   usage value (scaled by the helper)
    +0x10   table_size (unsigned)
    +0x18   occupancy (unsigned)
    +0x20   identity string (pointer +0x20, length +0x28)
    +0x40   14 x 8-byte entry values
    +0xb0   14 x 8-byte entry counters (zero skips the entry)
    +0x120  32-bit collections counter
    +0x124  32-bit last_copies counter
    +0x128  raw clock value stored at snapshot build time
    +0x130  commit-time clock value

The entry names come from the runtime-populated .bss table at
0x578c2e0, so they are parameters here, not claims from the binary.
The clock-chain nodes and the sentinel cell are parameters too: the
binary's sentinel cell (0x5777bc8) is runtime state.
"""

MASK64 = (1 << 64) - 1

ENTRY_COUNT = 14
SNAPSHOT_SIZE = 0x138
ENTRY_TABLE_BASE = 0x578C2E0
CLOCK_SENTINEL_CELL = 0x5777BC8
LAST_SECS_DIVISOR = 1000000.0
RATIO_MULTIPLIER = 100.0
HELPER_SCALE = 1.0 / 1024.0
HELPER_THRESHOLD = 1024.0
SECS_SINCE_MAGIC = 0x431BDE82D7B634DB


class ChainExhausted(Exception):
    """A sentinel-only chain ran out of nodes before an unconditional call."""


def saturating_window(commit, clock_value):
    """The 0x514df50 accessor: max(0, commit - clock) unsigned."""
    commit &= MASK64
    clock_value &= MASK64
    return commit - clock_value if commit >= clock_value else 0


def format_scaled(value):
    """The 0x5430570 helper: scale a value into KB/MB/GB/TB text.

    The input is treated as an unsigned 64-bit value (the helper's
    negative arm converts it as unsigned). The value is divided by
    1024 once, then again while the result is >= 1024.0, stepping
    KB -> MB -> GB -> TB (TB is terminal). Formatted ``%.2f %s``.
    """
    scaled = float(value & MASK64) * HELPER_SCALE
    unit = "KB"
    for nxt in ("MB", "GB", "TB"):
        if scaled < HELPER_THRESHOLD:
            break
        scaled *= HELPER_SCALE
        unit = nxt
    return "%.2f %s" % (scaled, unit)


def _format_double(value):
    """C++ default ostream formatting (6 significant digits)."""
    return format(value, ".6g")


def walk_clock_chain(nodes, sentinel):
    """The window's 3-node clock-chain walk.

    ``nodes`` is an ordered list of dicts with ``slot`` and ``call``
    (a zero-argument callable returning the clock value). The first
    node's slot is compared against ``sentinel``; the second node's
    slot against the first node's slot value; the third node is
    called unconditionally. A chain that runs out of nodes first
    raises :class:`ChainExhausted`, mirroring the binary, which
    would dereference a null link.
    """
    if not nodes:
        raise ChainExhausted("empty clock chain")
    first = nodes[0]["slot"]
    if first != sentinel:
        return nodes[0]["call"]()
    if len(nodes) < 2:
        raise ChainExhausted("sentinel-only chain of one node")
    if nodes[1]["slot"] != first:
        return nodes[1]["call"]()
    if len(nodes) < 3:
        raise ChainExhausted("sentinel-only chain of two nodes")
    return nodes[2]["call"]()


def secs_since(clock_value, commit):
    """(clock - commit) // 1,000,000, via the binary's magic divide.

    The window multiplies the unsigned-wraparound difference by
    0x431bde82d7b634db and shifts right by 82 (18 after the 128-bit
    multiply); that magic equals floor division by 1,000,000, the
    same divisor as last_secs, verified on edge and random values.
    """
    diff = (clock_value - commit) & MASK64
    return ((diff * SECS_SINCE_MAGIC) >> 82)


def format_report(snapshot, entry_names, clock_nodes, clock_sentinel):
    """Render the whole BlockCache report for one snapshot.

    ``snapshot`` maps field names (see the module docstring) to
    values: ``identity`` (str), ``capacity``, ``usage``,
    ``table_size``, ``occupancy``, ``counts`` (14 ints), ``values``
    (14 ints), ``collections``, ``last_copies``, ``clock_value``,
    ``commit``. ``entry_names`` is the 14 runtime table names.
    Returns the report string exactly as the window builds it.
    """
    if len(entry_names) != ENTRY_COUNT:
        raise ValueError("need %d entry names" % ENTRY_COUNT)
    if len(snapshot["counts"]) != ENTRY_COUNT:
        raise ValueError("need %d entry counters" % ENTRY_COUNT)
    if len(snapshot["values"]) != ENTRY_COUNT:
        raise ValueError("need %d entry values" % ENTRY_COUNT)
    out = []
    out.append("Block cache ")
    out.append(snapshot["identity"])
    out.append(" capacity: ")
    out.append(format_scaled(snapshot["capacity"]))
    out.append(" usage: ")
    out.append(format_scaled(snapshot["usage"]))
    out.append(" table_size: ")
    out.append(str(snapshot["table_size"] & MASK64))
    out.append(" occupancy: ")
    out.append(str(snapshot["occupancy"] & MASK64))
    out.append(" collections: ")
    out.append(str(snapshot["collections"] & 0xFFFFFFFF))
    out.append(" last_copies: ")
    out.append(str(snapshot["last_copies"] & 0xFFFFFFFF))
    out.append(" last_secs: ")
    window = saturating_window(snapshot["commit"],
                                snapshot["clock_value"])
    out.append(_format_double(window / LAST_SECS_DIVISOR))
    out.append(" secs_since: ")
    clock = walk_clock_chain(clock_nodes, clock_sentinel)
    out.append(str(secs_since(clock, snapshot["commit"])))
    out.append("\n")
    out.append("Block cache entry stats(count,size,portion):")
    capacity = snapshot["capacity"] & MASK64
    for name, count, value in zip(entry_names, snapshot["counts"],
                                  snapshot["values"]):
        if (count & MASK64) == 0:
            continue
        out.append(" ")
        out.append(name)
        out.append("(")
        out.append(str(count & MASK64))
        out.append(",")
        out.append(format_scaled(value))
        out.append(",")
        numerator = float(value & MASK64) * RATIO_MULTIPLIER
        if capacity == 0:
            ratio = float("nan") if (value & MASK64) == 0 else float("inf")
        else:
            ratio = numerator / float(capacity)
        out.append(_format_double(ratio))
        out.append("%)")
    out.append("\n")
    return "".join(out)
