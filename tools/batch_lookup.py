"""Python model of node #94 0x516d110: the batch lookup variant (RE-001).

The window (2951 bytes, FDE 0x1317268, LSDA 0xbd8cdf) is the batch
sibling of the #2009 probe-gated lookup 0x516ca20: same host gate
(+0xc18), same perf/timer prologue and epilogue, same 0x516c7e0
driver, but it works over a range-set object instead of one key
range: it collects the not-yet-done entries, probe-filters them,
then calls the driver once per passing entry.

Range-set layout (argument rdx, called "range-set" here):
  +0x00 base object: +0xe00 entry-pointer table, +0xf08 skip
          bitset word, +0xf10 counter
  +0x08 start index, +0x10 end index, +0x18 mask word A,
  +0x20 mask word B.  The skip word tested for an index is
  A | B | base+0xf08.
Entry layout (table slots): +0x08 key object, +0x20 a 16-byte
string view, +0x48 record object, +0x68 running maximum,
+0x80 pair slot, +0x88/+0x90 pair words, +0x71 driver byte.
"""

SEED = 0xBC9F1D34
MASK_CONST = 0x9E3779B97F4A7C13
MASK64 = (1 << 64) - 1


def skip_word(mask_a, mask_b, base_f08):
    """The skip word tested for an index: A | B | base+0xf08."""
    return mask_a | mask_b | base_f08


def probe_flag(options35, host_a60):
    """The -0x561 flag: options +0x35 when nonzero, else whether
    host +0xa60 is nonzero.  It is nonzero exactly when the #2003
    thunk would return null (options +0x35 and host +0xa60 not
    both zero)."""
    if options35:
        return options35
    return 1 if host_a60 else 0


def collect(entries, start, end, skip, flag, predicate, transform):
    """Collect the clear-bit entries in [start, end).

    entries maps an index to {"view": (ptr, length)}.  Set-bit
    indices are skipped.  When flag is nonzero the 16-byte view
    is copied directly from the entry; when flag is zero the
    entry's view must pass the host +0xc58 +0xa0 predicate and
    is then replaced by the +0x98 transform result view.
    Returns (views, indices) in scan order.
    """
    views, indices = [], []
    for idx in range(start, end):
        if (skip >> idx) & 1:
            continue
        entry = entries[idx]
        if flag:
            view = entry["view"]
        else:
            if not predicate(entry["view"]):
                continue
            view = transform(entry["view"])
        views.append(view)
        indices.append(idx)
    return views, indices


def _ror64(value, bits):
    return ((value >> bits) | (value << (64 - bits))) & MASK64


def probe_byte(hash32, table_count, table_words, rounds):
    """One collected view's probe byte (1 = pass, 0 = fail).

    base = (table_count * hash32) >> 32; round k tests
    table_words[base XOR k] against the two-bit mask of the
    64-bit product hash32 * 0x9e3779b97f4a7c13, rotated right
    12 per round.  Every tested round must contain both mask
    bits; round 0 is always tested even when rounds is 0.
    """
    base = (table_count * hash32) >> 32
    product = (hash32 * MASK_CONST) & MASK64
    for rnd in range(max(rounds, 1)):
        word = table_words[base ^ rnd]
        mask = (1 << (product & 63)) | (1 << ((product >> 6) & 63))
        if mask & ~word & MASK64:
            return 0
        product = _ror64(product, 12)
    return 1


def probe_filter(views, table_count, table_words, rounds, hash_fn):
    """Probe bytes for collected views, in order."""
    out = []
    for ptr, length in views:
        out.append(probe_byte(hash_fn(ptr, length, SEED),
                              table_count, table_words, rounds))
    return out


def driver_outcome(result_byte, flag_byte):
    """Driver out-byte protocol: a nonzero result byte takes the
    status-10 sweep path, else a nonzero flag byte takes the
    status-6 install, else the loop moves to the next item."""
    if result_byte:
        return "sweep"
    if flag_byte:
        return "status6"
    return "next"


def install_status(code, old_ptr):
    """Status install: the record becomes (code, 0, None) and a
    previously held pointer is freed (operator delete[])."""
    return (code, 0, None), old_ptr is not None


def pair_index(ptr, table18):
    """Pair index into the member +0x30 pair array, as in #2009:
    (ptr - table +0x18) / 8."""
    return (ptr - table18) // 8


def max_update(old_max, transform_result):
    """The member-feed maximum: updated only when larger."""
    return transform_result if transform_result > old_max else old_max


def mark_bit(word, idx):
    """Set one index bit in a skip word."""
    return word | (1 << idx)


def run_batch(host_c18, start, end, skip, flag, entries, probe_table,
              hash_fn, predicate, transform, driver_fn, member_feed_fn):
    """End-to-end model: collect, probe, then one driver call per
    passing entry.  probe_table is (count, words, rounds) or None
    (no probe table means the batch does nothing past the gate,
    as in the window).  driver_fn(entry) returns
    (result_byte, flag_byte).  member_feed_fn(entry) returns
    (transform_result, pair_or_None) and is only called when
    flag is zero.  Returns (events, records, done_word, counter).
    """
    events = []
    records = {i: e.get("record") for i, e in entries.items()}
    done_word = skip
    counter = 0
    if not host_c18:
        return ["early_gate"], records, done_word, counter
    if probe_table is None:
        return ["no_probe_table"], records, done_word, counter
    count, words, rounds = probe_table
    views, indices = collect(entries, start, end, skip, flag,
                             predicate, transform)
    events.append("collected:%d" % len(indices))
    probes = probe_filter(views, count, words, rounds, hash_fn)
    for view, idx, passed in zip(views, indices, probes):
        entry = entries[idx]
        if not passed:
            events.append("probe_fail:%d" % idx)
            done_word = mark_bit(done_word, idx)
            continue
        events.append("probe_pass:%d" % idx)
        if not flag:
            result, pair = member_feed_fn(entry)
            entry["max"] = max_update(entry.get("max", 0), result)
            if pair is not None:
                entry["string"] = pair
            events.append("member_feed:%d" % idx)
        result_byte, flag_byte = driver_fn(entry)
        outcome = driver_outcome(result_byte, flag_byte)
        events.append("driver_%s:%d" % (outcome, idx))
        if outcome == "sweep":
            done_word = mark_bit(done_word, idx)
            counter += entry.get("sweep_add", 0)
            for j in range(idx + 1, end):
                if j in entries and (done_word >> j) & 1 == 0:
                    records[j], _ = install_status(10, entries[j].get("record"))
                    done_word = mark_bit(done_word, j)
        elif outcome == "status6":
            records[idx], _ = install_status(6, entry.get("record"))
    return events, records, done_word, counter
