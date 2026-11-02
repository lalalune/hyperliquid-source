"""Model of node #94 MemtableIterator seek 0x5168610.

One window, extracted from the digest-verified work binary:
``0x5168610..0x5168a17`` (1031 bytes, FDE 0x1316e8c, LSDA 0xbd8ac4).

``seek(this, target) -> void`` where ``target`` is a slice (ptr, len)
whose last 8 bytes are the trailer.  The observed flow:

1. Perf prologue: the perf helper 0x52cd6e0 runs unconditionally; the
   TLS perf byte (fs:0-0x10a8) above 2 installs a timer record
   (object from 0x5242050, start value from its +0xa0 virtual, perf
   counter block TLS-0x350).  The perf-level slot 0x5777ef8 gates only
   the TLS getter calls, not the counters.
2. Probe-table gate: a null table object at this+0x28 skips straight
   to the inner seek.  Otherwise the probe length is
   ``target_len - 8 - comparator_holder+0x28`` (comparator holder at
   this+0x48).
3. Prefix chain: up to four objects linked via +0x20, consulted on
   progressively 8-byte-shorter slices (probe_len, -8, -16, -24).  At
   each of the first three levels, when the object's +0xa0 virtual is
   exactly the known function 0x5165f20 (the RELATIVE relocation at
   slot 0x5778400), the call is skipped and the chain descends; any
   other virtual is called on that level's slice.  The fourth level
   always calls its +0xa0 virtual.  A called predicate returning False
   sends control to the inner seek without probing.
4. Probe: the first prefix object's +0x98 virtual transforms the
   first slice; the result is hashed by 0x5422e70 with seed
   0xbc9f1d34.  With table count ``n`` (u32 at +0x0), rounds ``r``
   (u32 at +0x4) and words at +0x8, the base index is
   ``(n * hash32) >> 32``.  Round ``k`` tests word ``words[base ^ k]``
   against the two-bit mask from the rotated hash: bits
   ``(h & 63)`` and ``((h >> 6) & 63)``; the hash is the 64-bit product
   ``hash32 * 0x9e3779b97f4a7c13`` rotated right 12 each round.  Round
   0 is always tested, even when ``r`` is 0.  A mask bit clear in the
   word is a miss: ready is set False and the function returns with
   no inner seek and no refresh.
5. Inner seek (probe hit, predicate False, or null table): the inner
   iterator at this+0x50 is positioned with its +0x30 virtual on the
   target slice, its +0x10 virtual result is stored to this+0x58
   (ready), and the refresh handler 0x51684d0 runs.
6. Counters: perf byte above 1 increments the +0x140 counter at entry,
   +0x200 on a probe hit, +0x208 on a probe miss.  The timer record,
   when its stored start value is nonzero, is destroyed on exit by
   0x5165320, which adds (end value from the +0xa0 virtual minus the
   start value) to the +0x138 counter.

Unresolved (recorded, not modelled): the identity of 0x5242050 and of
the +0xa0 virtual's return beyond its timer role; why the known
function 0x5165f20 passes a level without a call; the identity of the
perf helper 0x52cd6e0; the hash 0x5422e70 internals (modelled here by
an injectable hash function, as in the neighbouring packets).
"""

MASK64 = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C13
HASH_SEED = 0xBC9F1D34
KNOWN_A0 = 0x5165F20


def probe_mask(rotated_hash):
    """The two-bit mask a probe round tests against a table word."""
    return (1 << (rotated_hash & 63)) | (1 << ((rotated_hash >> 6) & 63))


def probe_base(count, hash32):
    """Base index: (count * hash32) >> 32, both 32-bit inputs."""
    return ((count & 0xFFFFFFFF) * (hash32 & 0xFFFFFFFF)) >> 32


class PrefixObject:
    """One prefix-chain object.

    ``a0`` is either the string ``"known"`` (its +0xa0 virtual is
    exactly 0x5165f20, so the call is skipped) or a callable taking a
    (ptr, len) slice and returning a bool.  ``next_obj`` is the +0x20
    link.  ``transform`` is the +0x98 virtual, used only on the first
    object; it takes a slice and returns a (ptr, len) pair.
    """

    def __init__(self, a0, next_obj=None, transform=None):
        self.a0 = a0
        self.next_obj = next_obj
        self.transform = transform


class ProbeTable:
    """The this+0x28 table: u32 count, u32 rounds, word list."""

    def __init__(self, count, rounds, words):
        self.count = count
        self.rounds = rounds
        self.words = words


class InnerIterator:
    """The this+0x50 iterator: +0x30 Seek, +0x10 Valid."""

    def __init__(self, valid_result=True):
        self.valid_result = valid_result
        self.events = []

    def seek(self, target):
        self.events.append(("seek", target))

    def valid(self):
        self.events.append(("valid",))
        return self.valid_result


class PerfState:
    """TLS perf byte, perf-level slot, and counters by offset."""

    def __init__(self, level=0, slot_nonzero=False):
        self.level = level
        self.slot_nonzero = slot_nonzero
        self.counters = {0x140: 0, 0x200: 0, 0x208: 0, 0x138: 0}
        self.getter_calls = 0
        self.helper_calls = 0

    def getter(self):
        if self.slot_nonzero:
            self.getter_calls += 1

    def helper(self):
        self.helper_calls += 1


def run_seek(target, table, prefix, comparator_word, inner, perf,
             hash_fn, timer_clock=None):
    """Run the 0x5168610 model.

    ``target`` is a (ptr, len) pair; ``timer_clock`` supplies the
    +0xa0 virtual end value for the timer destructor, or None when no
    timer record exists.  Returns a dict with the final ready flag,
    the event log, and the perf state.  Refresh is reported as an
    event (the 0x51684d0 handler is modelled by the neighbouring
    packet, not here).
    """
    events = []
    ready = None
    timer_start = None

    # 1. Perf prologue.
    perf.helper()
    perf.getter()
    if perf.level > 2:
        # Timer record installed (object from 0x5242050, start value
        # from its +0xa0 virtual); the caller supplies the start
        # value through timer_clock's paired start, see run below.
        timer_start = timer_clock[0] if timer_clock else None
    # Perf-level-1 block.
    perf.getter()
    if perf.level > 1:
        perf.helper()
        perf.counters[0x140] += 1

    def destroy_timer():
        if timer_start:
            end = timer_clock[1]()
            perf.counters[0x138] += (end - timer_start) & MASK64
            events.append(("timer_destroyed", timer_start, end))

    def inner_seek():
        nonlocal ready
        inner.seek(target)
        ready = inner.valid()
        events.append(("refresh_84d0",))
        if timer_start:
            destroy_timer()

    # 2/3. Probe-table gate and prefix chain.
    if table is None:
        events.append(("table_null_skip_probe",))
        inner_seek()
        return {"ready": ready, "events": events, "perf": perf,
                "inner_events": inner.events}
    target_ptr, target_len = target
    probe_len = target_len - 8 - comparator_word
    obj = prefix
    predicate_passed = True
    for level in range(4):
        slice_len = probe_len - 8 * level
        sl = (target_ptr, slice_len)
        events.append(("chain_level", level, sl))
        if level < 3 and obj.a0 == "known":
            events.append(("chain_known_skip", level))
            obj = obj.next_obj
            continue
        result = obj.a0(sl) if callable(obj.a0) else True
        events.append(("chain_call", level, result))
        if not result:
            predicate_passed = False
            break
        if level < 3:
            obj = obj.next_obj
    if not predicate_passed:
        events.append(("predicate_false_inner_seek",))
        inner_seek()
        return {"ready": ready, "events": events, "perf": perf,
                "inner_events": inner.events}

    # 4. Probe.
    transformed = prefix.transform((target_ptr, probe_len))
    h = hash_fn(transformed, HASH_SEED)
    hash32 = h & 0xFFFFFFFF
    base = probe_base(table.count, hash32)
    events.append(("probe", transformed, h, base))
    rotated = (hash32 * GOLDEN) & MASK64
    hit = True
    round_no = 0
    while True:
        word = table.words[base ^ round_no]
        mask = probe_mask(rotated)
        events.append(("probe_round", round_no, word, mask))
        if mask & (~word & MASK64):
            hit = False
            break
        if round_no + 1 < table.rounds:
            rotated = ((rotated >> 12) | (rotated << 52)) & MASK64
            round_no += 1
            continue
        break
    if not hit:
        perf.getter()
        if perf.level > 1:
            perf.helper()
            perf.counters[0x208] += 1
        ready = False
        events.append(("probe_miss_ready_false",))
        if timer_start:
            destroy_timer()
        return {"ready": ready, "events": events, "perf": perf,
                "inner_events": inner.events}

    # 5. Probe hit: perf block, then the inner seek.
    perf.getter()
    if perf.level > 1:
        perf.helper()
        perf.counters[0x200] += 1
    events.append(("probe_hit_inner_seek",))
    inner_seek()
    return {"ready": ready, "events": events, "perf": perf,
            "inner_events": inner.events}
