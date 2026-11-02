"""Node #115 memtable iterator seek gate (0x5f08c40) model.

Validates the #94 seek-gate mapping (RE-001, window 0x5168610) against
node #115 under RE-014: same behavior shape, #115 addresses, layouts
and constants. Every rule below is pinned to the verbatim disassembly
in research/work-items/RE-014-memtable-iterator-seek-gate-115/.

Field layout of ``this`` (rbx): probe-table object at +0x28 (or null),
prefix-chain object at +0x30, comparator holder at +0x48, inner
iterator at +0x50, ready flag at +0x58. The target is a slice pointer
(ptr at +0x0, len at +0x8) whose last 8 bytes are the trailer.
"""

KNOWN_FN = 0x5F06550
HASH_SEED = 0xBC9F1D34
MASK_CONST = 0x9E3779B97F4A7C13
MASK64 = (1 << 64) - 1

PERF_LEVEL_GOT = 0x64ED2B0
KNOWN_FN_GOT = 0x64ED7B8
PERF_HELPER = 0x606DD10
TIMER_FACTORY = 0x5FE2680
TIMER_DESTROY = 0x5F05950
PROBE_HASH = 0x61C34A0
REFRESH = 0x5F08B00


def probe_len(target_len, holder_plus_0x28):
    """Probe length: target_len - 8 (trailer) - holder+0x28."""
    return target_len - 8 - holder_plus_0x28


def chain_slice_lens(plen):
    """Four chain slices: plen, plen-8, plen-16, plen-24."""
    return [plen, plen - 8, plen - 16, plen - 24]


def probe_base(count, hash32):
    """Base word index: (count * hash32) >> 32."""
    return (count * hash32) >> 32


def mask_bits(h64):
    """Two-bit mask positions of a rotated hash value."""
    return (h64 & 63, (h64 >> 6) & 63)


def ror12(h64):
    """Rotate a 64-bit value right by 12."""
    return ((h64 >> 12) | ((h64 << 52) & MASK64)) & MASK64


def probe(words, base, rounds, hash32):
    """Probe filter. Returns True on hit, False on miss.

    Round k tests words[base XOR k] against the two mask bits of the
    current rotated hash. The hash starts as hash32 * MASK_CONST and
    rotates right 12 after each non-final round. Round 0 is always
    tested, even when rounds is 0, so max(rounds, 1) rounds run.
    """
    h = (hash32 * MASK_CONST) & MASK64
    for k in range(max(rounds, 1)):
        b0, b1 = mask_bits(h)
        word = words[base ^ k]
        if not (word & (1 << b0)) or not (word & (1 << b1)):
            return False
        h = ror12(h)
    return True


def chain_gate(levels):
    """Prefix-chain gate. Returns 'probe' or 'inner'.

    ``levels`` is a list of four (virtual, predicate) pairs, where
    ``predicate`` is the bool the +0xa0 virtual would return if called
    (ignored when the level is skipped). At each of the first three
    levels, a virtual exactly equal to KNOWN_FN is skipped and the
    chain descends; any other virtual is called: False goes to the
    inner seek, True goes straight to the probe. The fourth level is
    always called with the same two outcomes.
    """
    for i, (virtual, predicate) in enumerate(levels):
        if i < 3 and virtual == KNOWN_FN:
            continue
        return "probe" if predicate else "inner"
    raise AssertionError("fourth level must call, never skip")


def seek_gate(table, holder28, target_len, levels, words, count,
              rounds, hash32, perf_byte, timer_start, timer_end,
              inner_valid):
    """Whole seek gate. Returns (outcome, ready, counters, timer_add).

    outcome is 'inner' (inner seek + valid + refresh ran) or 'miss'
    (ready False, no inner seek, no refresh). counters maps the perf
    counter offsets (+0x140 entry, +0x200 hit, +0x208 miss) to their
    increments; all are gated on perf_byte > 1. timer_add is
    timer_end - timer_start when the timer was installed
    (perf_byte > 2) and its start value is nonzero, else None; the
    timer record is destroyed on every exit path in that case.
    """
    counters = {}
    if perf_byte > 1:
        counters[0x140] = 1
    timer_add = None
    if perf_byte > 2 and timer_start:
        timer_add = timer_end - timer_start

    def inner():
        return ("inner", inner_valid, counters, timer_add)

    if table is None:
        return inner()
    if chain_gate(levels) == "inner":
        return inner()
    if probe(words, probe_base(count, hash32), rounds, hash32):
        if perf_byte > 1:
            counters[0x200] = 1
        return inner()
    if perf_byte > 1:
        counters[0x208] = 1
    return ("miss", False, counters, timer_add)
