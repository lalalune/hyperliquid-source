"""Model of node #94 probe-gated lookup (RE-001, 0x516ca20).

The lookup turns a key range into a driver call, gated by a probe
filter.  Semantics pinned from the window disassembly (see
research/work-items/RE-001-probe-gated-lookup-94/):

- host +0xc18 null returns 0 at once, with nothing else done;
- the member comes from the 0x516aa20 thunk (built in #2003: null
  unless the options argument +0x35 and host +0xa60 are both zero,
  else the #2003 sharded access); a null member skips key handling;
- the key slice is range start..end-8; the transform 0x51922d0
  result max-updates the stack-arg-0x18 output (only when larger)
  and, when the r8 string argument is non-null, replaces that
  string wholesale with the pair looked up from the member +0x68
  table via the member +0x90 pointer;
- the probe slice is range start with length
  (end - start - 8) - (host +0x10 object) +0x28; a null table at
  host +0xc60 skips the probe; host +0x30 byte zero takes the
  virtual variant (predicate virtual, then transform virtual whose
  result is hashed), nonzero takes the direct-hash variant; the
  loop is the #1994 probe (base, two-bit mask, ror 12, round 0
  always tested);
- a probe hit calls the driver 0x516c7e0; a miss writes -1 to the
  stack-arg-0x20 output and, when the r9-object flag says so,
  installs the {6, 0, null} record into the r9 object (skipped
  when its first byte is already 2; the post-move temporary free
  is dead because the move zeroes the temporary pointer);
- after the driver returns, the -0x82 out byte is the return
  value and the -0x81 out byte gates the same status install;
- the epilogue releases a non-null member through its +0x8
  virtual, destroys the timer record when its start value is
  nonzero, and returns the -0x82 byte.

Contract callees (hash 0x5422e70, the probe virtuals, the driver,
the transform's first call 0x51910a0 and comparator) are injected
as callables, so the tests exercise the pinned control flow and
arithmetic without claiming those callees' internals.
"""

SEED = 0xBC9F1D34
MASK_CONST = 0x9E3779B97F4A7C13
MASK64 = (1 << 64) - 1


def ror64(value, bits):
    return ((value >> bits) | (value << (64 - bits))) & MASK64


def probe_check(words, count, rounds, hash32):
    """Return True on a probe hit, False on a miss.

    words is the table's word list, count the table count field,
    rounds the table +0x4 field, hash32 the 32-bit hash value.
    Mirrors the window loop exactly: base = (count * hash32) >> 32,
    the two-bit mask of hash32 * MASK_CONST rotated right 12 after
    each passing round, round 0 always tested even when rounds is 0.
    """
    base = (count * hash32) >> 32
    prod = (hash32 * MASK_CONST) & MASK64
    k = 0
    while True:
        mask = (1 << (prod & 63)) | (1 << ((prod >> 6) & 63))
        word = words[base ^ k]
        if k + 1 < rounds:
            if mask & (~word & MASK64):
                return False
            prod = ror64(prod, 12)
            k += 1
            continue
        return (mask & (~word & MASK64)) == 0


def probe_length(range_start, range_end, holder_adj):
    """Probe slice length: (end - start - 8) - holder +0x28."""
    return (range_end - range_start - 8) - holder_adj


def key_slice_length(range_start, range_end):
    """Key slice length: end - start - 8 (trailer stripped)."""
    return range_end - range_start - 8


def pair_index(member90_ptr, table18_base):
    """Index into the 16-byte pair array from the +0x90 pointer."""
    return (member90_ptr - table18_base) // 8


def transform_lookup(gate_known, gate_virtual_result, table_present,
                     table_empty, at_end, comparator_result,
                     member90_value):
    """Model of 0x51922d0's decision tree.

    gate_known: the member vtable +0x10 slot equals 0x518e2c0.
    gate_virtual_result: the +0x10 virtual's boolean result when
    the slot differs (None when gate_known).  comparator_result:
    the comparator virtual's integer result (None when the walk
    returns early).  Returns 0 or the qword at *member +0x90.
    """
    if not gate_known:
        if not gate_virtual_result:
            return 0
    if not table_present:
        return 0
    if table_empty:
        return 0
    if at_end:
        return 0
    if comparator_result is None or comparator_result > 0:
        return 0
    return member90_value


def move_record(dst, src):
    """Model of 0x5164ce0: move a {6-byte header, pointer} record.

    dst and src are [header_bytes_6, pointer] lists.  The source is
    zeroed, the destination's previous pointer is returned so the
    caller can free it (the window's caller then frees the moved
    temporary pointer, which is already null, so that free is dead).
    A source equal to the destination returns None unchanged.
    """
    if dst is src:
        return None
    old_pointer = dst[1]
    dst[0] = src[0]
    dst[1] = src[1]
    src[0] = b"\x00" * 6
    src[1] = None
    return old_pointer


class LookupResult(object):
    def __init__(self):
        self.return_value = 0
        self.events = []
        self.counters = {"plus_0x120": 0, "plus_0x200": 0, "plus_0x208": 0}
        self.out_max = None
        self.out_string = None
        self.out_sentinel = None
        self.status = None


def scan(host_c18, member, range_start, range_end, holder_adj,
         out_max, out_string, pairs, table18_base, member90_ptr,
         transform_result, probe_table, raw_mode, r9_first_byte,
         predicate_result, transform_pair, hash_fn, driver,
         timer_start):
    """Run the pinned lookup flow.

    member: None, or a dict with 'table18' and 'pairs' is not needed
    here — the pair lookup uses pairs/table18_base/member90_ptr
    directly.  transform_result: the 0x51922d0 return value (None
    when member is None).  probe_table: None, or a dict with
    count/words/rounds.  predicate_result: the +0xa0 virtual's
    boolean (virtual variant only).  transform_pair: the +0x98
    virtual's (pointer, length) result (virtual variant only).
    hash_fn: (pointer, length, seed) -> hash32.  driver: a callable
    returning (out82, out81).  timer_start: 0 or nonzero.
    out_max/out_string/out_sentinel are single-item lists acting as
    the caller's output slots (out_string None means the r8 string
    argument itself is null).  Returns a LookupResult.
    """
    res = LookupResult()
    res.out_max = out_max
    res.out_string = out_string
    res.out_sentinel = None
    if not host_c18:
        res.return_value = 0
        res.events.append("early_gate")
        return res
    out82 = 0
    out81 = 0
    member_resolved = member is not None
    if member_resolved:
        if transform_result is not None and transform_result > out_max[0]:
            out_max[0] = transform_result
            if out_string is not None:
                idx = pair_index(member90_ptr, table18_base)
                out_string[0] = pairs[idx]
                res.events.append("string_replaced")
        elif transform_result is not None:
            res.events.append("max_unchanged")
    # Probe setup: the -0x81 flag is (r9 first byte == 6) until the
    # driver overwrites it through its out pointer.
    out81 = 1 if r9_first_byte == 6 else 0
    probe_len = probe_length(range_start, range_end, holder_adj)
    hit = None
    driver_called = False
    if probe_table is None:
        driver_called = True
    elif raw_mode:
        hash32 = hash_fn(range_start, probe_len, SEED)
        hit = probe_check(probe_table["words"], probe_table["count"],
                          probe_table["rounds"], hash32)
    else:
        if not predicate_result:
            driver_called = True
        else:
            ptr, length = transform_pair
            hash32 = hash_fn(ptr, length, SEED)
            hit = probe_check(probe_table["words"], probe_table["count"],
                              probe_table["rounds"], hash32)
    if hit is False:
        res.counters["plus_0x208"] += 1
        res.events.append("probe_miss")
        res.out_sentinel = -1
        if out81:
            install_status(res, r9_first_byte)
        driver_called = False
    if hit is True:
        res.counters["plus_0x200"] += 1
        res.events.append("probe_hit")
        driver_called = True
    if driver_called:
        res.events.append("driver_called")
        out82, out81 = driver()
        if out82:
            res.events.append("driver_done")
        elif out81:
            install_status(res, r9_first_byte)
    # Epilogue.
    res.counters["plus_0x120"] += 1
    res.return_value = out82
    if member_resolved:
        res.events.append("member_released")
    if timer_start:
        res.events.append("timer_destroyed")
    return res


def install_status(res, r9_first_byte):
    """The status-6 install: skipped when the first byte is already 2."""
    if r9_first_byte == 2:
        res.events.append("status_skip_byte2")
        return
    res.status = (b"\x06\x00\x00\x00\x00\x00", None)
    res.events.append("status6_installed")
