"""Model for the node #115 batch lookup 0x5f0d740 (RE-014 validation).

Every rule below is pinned to the verbatim disassembly in
research/work-items/RE-014-batch-lookup-115/. The hash routine
itself (0x61c34a0) is taken by contract — it is byte-identical to
#94's hash per the RE-014 probe-gated-lookup-115 packet — while the
probe filter math, the flag rules, the driver outcomes and the
sweep are modeled and tested here.
"""

MASK64 = (1 << 64) - 1
MASK_CONST = 0x9E3779B97F4A7C13
SEED = 0xBC9F1D34


def ror12(x):
    """64-bit rotate right by 12, as the probe loop applies per round."""
    x &= MASK64
    return ((x >> 12) | ((x & 0xFFF) << 52)) & MASK64


def probe_base(count, hash32):
    """(count * hash32) >> 32, the probe table base index."""
    return (count * hash32) >> 32


def probe_mask(prod):
    """Two-bit mask of the 64-bit product: bits (prod & 63) and
    ((prod >> 6) & 63)."""
    return (1 << (prod & 63)) | (1 << ((prod >> 6) & 63))


def probe_passes(hash32, count, words, rounds):
    """True when every tested round's word contains both mask bits.

    Round k tests words[base XOR k] against the mask of the product
    ror'd k times; round 0 is always tested even when rounds is 0.
    """
    base = probe_base(count, hash32)
    prod = (hash32 * MASK_CONST) & MASK64
    n = rounds if rounds >= 1 else 1
    for k in range(n):
        mask = probe_mask(prod)
        if words[base ^ k] & mask != mask:
            return False
        prod = ror12(prod)
    return True


def batch_flag(options35, host_a60):
    """Stack -0x561: options +0x35 when nonzero, else 1 when
    host +0xa60 is nonzero, else 0."""
    if options35:
        return options35
    return 1 if host_a60 else 0


def collect_direct(c58_present, host30):
    """Stack -0x578: 1 when host +0xc58 is null, else the host +0x30
    byte. True means copy the view directly; False means run the
    predicate/transform path."""
    return not (c58_present and host30 == 0)


def skip_word(base_skip, range18, range20):
    """Skip bitset word: base +0xf08 OR range +0x18 OR range +0x20."""
    return base_skip | range18 | range20


def pair_index(ptr, table):
    """(ptr - (table + 0x18)) / 8, the member-feed pair index."""
    return (ptr - (table + 0x18)) // 8


def pair_address(table, index):
    """table + 0x30 + index * 16, the looked-up pair address."""
    return table + 0x30 + index * 16


def max_update(old, new):
    """Entry +0x68 max-update: the new value wins only when larger."""
    return new if new > old else old


def driver_outcome(result_byte, flag_byte):
    """'sweep' when the driver result byte is nonzero, 'status6'
    when only the flag byte is set, else 'next'."""
    if result_byte:
        return "sweep"
    if flag_byte:
        return "status6"
    return "next"


def sweep_aftermath(f10, options78, later_clear):
    """After the sweep move and callback: when base +0xf10 reaches
    options +0x78 the fill is skipped and the driver loop resumes;
    otherwise every later clear entry is filled and reaching the
    range end ends the function via the epilogue."""
    if f10 >= options78:
        return ("resume", [])
    return ("epilogue", list(later_clear))


def run_batch(n, skip, flag, probe_present, probe_pass, driver,
              second_word, f10, options78):
    """End-to-end batch run at model level.

    n: range size; skip: indices already set in the skip bitset;
    flag: driver flag (nonzero takes the direct driver path);
    probe_present: host +0xc60 non-null; probe_pass: index -> bool
    for collected entries; driver: index -> 'sweep'/'status6'/'next';
    second_word: index -> word added to base +0xf10 on a sweep.
    Returns (records, counters, f10, ended) where records maps an
    index to its installed (code, subcode, detail) triple,
    counters holds probe hit/miss counts (perf byte > 1 assumed),
    and ended is 'sweep-epilogue' or 'normal'.
    """
    clear = [i for i in range(n) if i not in skip]
    done = set()
    counters = {"hit": 0, "miss": 0}
    if flag and probe_present and clear:
        for i in clear:
            if probe_pass.get(i):
                counters["hit"] += 1
            else:
                done.add(i)
                counters["miss"] += 1
    records = {}
    ended = "normal"
    for i in range(n):
        if i in skip or i in done:
            continue
        outcome = driver.get(i, "next")
        if outcome == "sweep":
            f10 += second_word.get(i, 0)
            skip = set(skip) | {i}
            later = [j for j in range(i + 1, n)
                     if j not in skip and j not in done]
            how, filled = sweep_aftermath(f10, options78, later)
            for j in filled:
                records[j] = (10, 0, None)
            if how == "epilogue":
                ended = "sweep-epilogue"
                break
        elif outcome == "status6":
            records[i] = (6, 0, None)
    return records, counters, f10, ended
