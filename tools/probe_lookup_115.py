"""Model of node #115's probe-gated lookup (RE-014, 0x5f0d050),
validated against node #94's merged packet (0x516ca20, PR #2009).

Semantics pinned from the #115 window disassembly (see
research/work-items/RE-014-probe-gated-lookup-115/):

- host +0xc18 null returns 0 at once, with nothing else done;
- the member comes from the 0x5f0b050 thunk (null unless the
  options argument +0x35 and host +0xa60 are both zero, else the
  sharded access 0x5f0a9c0 by contract); a null member skips key
  handling;
- the key slice is range start..end-8; the transform 0x5f32900
  result (by contract) max-updates the stack-arg-0x18 output (only
  when larger) and, when the r8 string argument is non-null,
  replaces that string wholesale with the pair looked up from the
  member +0x68 table via the member +0x90 pointer;
- the probe slice is range start with length
  (end - start - 8) - (host +0x10 object) +0x28; a null table at
  host +0xc60 skips the probe; host +0x30 byte zero takes the
  virtual variant (predicate virtual, then transform virtual whose
  result is hashed), nonzero takes the direct-hash variant; the
  loop is the #94 probe exactly (base, two-bit mask, ror 12,
  round 0 always tested);
- a probe hit calls the driver 0x5f0ce10 (by contract); a miss
  stores the literal qword 0x00ffffffffffffff to the stack-arg-0x20
  output slot and, when the r9-object flag says so, installs the
  {6, 0, null} record into the r9 object (skipped when its first
  byte is already 2; the post-move temporary free is dead because
  the move zeroes the temporary pointer);
- after the driver returns, the -0x82 out byte is the return
  value and the -0x81 out byte gates the same status install;
- the epilogue releases a non-null member through its +0x8
  virtual, destroys the timer record when its start value is
  nonzero, and returns the -0x82 byte.

The hash 0x61c34a0 is byte-identical to node #94's 0x5422e70, so
its transcription here is the #115 function itself, not a borrow:
eax = length * 0xc6a4a793 XOR seed; per 4-byte word: add the word,
multiply by 0xc6a4a793, xor with (value >> 16); tail bytes added
with shifts 0/8/16, final multiply by 0xc6a4a793, xor with
(value >> 24). Empty input returns the seed.

Contract callees (the transform, the probe virtuals, the driver)
are injected as callables, so the tests exercise the pinned
control flow and arithmetic without claiming those callees'
internals. Perf counters are recorded as path events; the TLS
byte > 1 gate on the +0x120/+0x200/+0x208 counters is documented
in the packet README.
"""

SEED = 0xBC9F1D34
MASK_CONST = 0x9E3779B97F4A7C13
HASH_MULT = 0xC6A4A793
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
MISS_LITERAL = 0x00FFFFFFFFFFFFFF


def ror64(value, bits):
    return ((value >> bits) | (value << (64 - bits))) & MASK64


def hash115(data, seed):
    """Node #115 hash 0x61c34a0: (bytes, seed) -> 32-bit hash."""
    eax = ((len(data) * HASH_MULT) & MASK32) ^ (seed & MASK32)
    nwords = len(data) // 4
    for i in range(nwords):
        word = int.from_bytes(data[i * 4:(i + 1) * 4], "little")
        eax = (eax + word) & MASK32
        eax = (eax * HASH_MULT) & MASK32
        eax ^= eax >> 16
    tail = data[nwords * 4:]
    if len(tail) >= 3:
        eax = (eax + (tail[2] << 16)) & MASK32
    if len(tail) >= 2:
        eax = (eax + (tail[1] << 8)) & MASK32
    if len(tail) >= 1:
        edx = (eax + tail[0]) & MASK32
        edx = (edx * HASH_MULT) & MASK32
        eax = edx ^ (edx >> 24)
    return eax


def probe_check(words, count, rounds, hash32):
    """Return True on a probe hit, False on a miss.

    Mirrors the #115 window loop exactly: base = (count * hash32)
    >> 32, the two-bit mask of hash32 * MASK_CONST rotated right 12
    after each passing round, round 0 always tested even when
    rounds is 0.
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


def thunk_guard(options_35, host_a60):
    """The 0x5f0b050 guard: member only when both bytes are zero."""
    return options_35 == 0 and host_a60 == 0


def move_record(dst, src):
    """Model of 0x5f05310: move a {6-byte header, pointer} record.

    dst and src are [header_bytes_6, pointer] lists. The source is
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
    """Run the pinned #115 lookup flow.

    Arguments mirror the merged #94 model's scan (PR #2009; removed
    from the tree by the 8fd8db68 migration, now in Git history),
    with the #115 miss literal: out_sentinel is
    0x00ffffffffffffff, not -1.
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
        res.out_sentinel = MISS_LITERAL
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
