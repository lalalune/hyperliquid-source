"""Model of node #115's memtable iterator seek loop (window 0x5f09050).

RE-014 work item: validates the merged #94 seek-loop mapping (RE-001,
window 0x5168a20) against node #115. The binary function is void: it
positions an inner iterator at a target internal key, optionally after
a hash-table probe, then loops: refresh, status snapshot, key-slice
fill, compare, advance. This model pins the loop's control flow and
field effects exactly as observed in
research/work-items/RE-014-memtable-iterator-seek-loop-115/; the inner
iterator's own Seek positioning, the hash callee, the comparator
implementation and the refresh handler internals are supplied as hooks,
because the window calls them through virtuals / by contract instead of
inlining them.

Binary facts (window 0x5f09050..0x5f09850, 2048 bytes, FDE 0x7455cc):
- Args: this (fields below) and a target key slice (ptr, len) whose last
  8 bytes are the trailer. The user key is the slice minus the trailer.
- this fields: +0x28 probe-table object or null, +0x30 prefix object,
  +0x48 comparator holder, +0x50 inner iterator, +0x58 ready flag,
  +0x60 check width, +0x68 installed code, +0x6c subcode, +0x70 detail
  string, +0x78 report context.
- Perf prologue: helper 0x606dd10 runs unconditionally at entry; the
  perf-level slot 0x64ed2b0 (GLOB_DAT for the rocksdb perf_level
  thread-local) gates only the TLS getter calls (0x63f0fe0), not the
  counters. TLS perf byte at fs:0-0x10b0 (note: #94 used fs:0-0x10a8).
  When the byte exceeds 2 at entry, the 0x5fe2680 prologue runs and its
  acquired pointer is destroyed via 0x5f05950 (91 bytes) on exit when
  non-null; the timer counter block is TLS-0x350 + 0x138. When the byte
  exceeds 1, helper calls increment counters at TLS-0x350 offsets
  +0x140 (entry path), +0x200 (probe hit), +0x208 (probe miss),
  +0x0 (fill path) and +0x150 (advance path).
- Probe (skipped when +0x28 is null or the +0xa0 gate virtual on the
  +0x30 object is false): probe slice = (target ptr, target len - 8 -
  the +0x48 object's +0x28 word). The +0x98 virtual's (ptr, len) return
  is hashed by 0x61c34a0 with seed 0xbc9f1d34 (133 bytes, byte-identical
  to #94's 0x5422e70 per the RE-014 probe-gated-lookup-115 packet).
  Base index = (count * hash32) >> 32 with count = table +0x0 (u32);
  each round r tests word table[base ^ r] against a two-bit mask from
  hash32 * 0x9e3779b97f4a7c13: bits (h & 63) and ((h >> 6) & 63); a
  missing bit is a miss. The hash rotates right 12 (64-bit ror) each
  round; the loop runs table +0x4 (u32) rounds, but always tests at
  least the round-0 word, and prefetches table[base] first. Miss: ready
  = False and the function returns. Hit: continue.
- Inner seek: inner +0x30 virtual with the target, then inner +0x10
  virtual, stored to ready. Then the refresh handler 0x5f08b00 runs
  (308 bytes, FDE 0x7455cc neighbour range 0x5f08b00..0x5f08c34).
- Predicate gate (vtable +0x10 vs known 0x5f04de0, 20 bytes): known
  means ready nonzero AND code zero; unknown calls the +0x10 virtual.
  Known clean goes straight to the fill gate. Otherwise the status copy
  runs: for the known flavor this is ready False or code set; for the
  unknown flavor it is a False return (a True return goes straight to
  the fill gate -- this polarity is verified against the #115 jumps at
  0x5f09778..0x5f09789 and corrects the reversed "when" line in the
  #94 packet's records.json, whose own bytes show the same direction:
  unknown True jumps to the fill gate at 0x51690ee). The copy itself:
  the installed record (code, sub, detail) is copied to a stack
  record; the vtable +0x68 slot is a Status() virtual called with
  (record out-pointer, this) when it differs from the known
  implementation 0x5f05680 (GOT 0x64ed790), otherwise the copy is
  inlined, deep-copying the detail string via 0x61cf610 (63 bytes).
  Copy code nonzero: the copy's detail is freed and the flow rejoins
  the fill gate. Copy code zero: the +0x20 gate runs (any slot other
  than the 0x5f08320 handler from GOT 0x64ed7d0 is called with this;
  the 0x5f08320 flavor runs the inline sequence: inner +0x50 virtual,
  inner +0x10 valid stored to ready, refresh 0x5f08b00) and the flow
  rejoins the fill gate.
- Fill gate: known predicate re-checks ready AND code == 0, else return;
  unknown predicate is called again (a second call) and must be True,
  else return. Fill: the key provider gate (vtable +0x50 vs the default
  provider 0x5f05e10, 107 bytes, from GOT 0x64ed7b0) inlines the
  length-prefix parse of the inner +0x18 buffer, otherwise calls the
  +0x50 virtual; the current slice is (entry ptr, parsed length - 8).
- Compare: the +0x10 virtual of the +0x48 object's +0x20 subobject is
  called with the target and current slices; observed sign-to-action
  mapping: positive stops the seek, zero falls to the trailer check,
  negative advances. Trailer check (only on a zero compare): the entry
  trailer qword (8 bytes at entry + user length) vs the target trailer
  qword (last 8 bytes of the target), unsigned; entry trailer below the
  target trailer advances, otherwise the seek stops.
- Advance: the +0x48 gate (vtable +0x48 vs the 0x5f08470 handler from
  GOT 0x64ed7d8, 391 bytes) inlines inner +0x28 (next) then inner +0x10
  (valid -> ready) for the known flavor, otherwise calls the +0x48
  virtual. Then, when width is nonzero, the predicate gate runs again
  (known: ready and code == 0; unknown: call, and a False first call
  rejoins the fill gate, which calls it a second time). On a passing
  gate the entry check 0x5f07670 runs as reader(record, buffer, width,
  0) and its code/sub/detail install to +0x68/+0x6c/+0x70, freeing the
  previous detail with array delete after the install. A nonzero
  installed code reports via 0x5fceda0 (243 bytes) at level 3, context
  +0x78, format "[%s:538] In MemtableIterator: %s", file
  "db/memtable.cc", detail +0x70, and rejoins the fill gate -- which,
  for the known predicate, returns at once because the code is still
  set, while for an unknown predicate that still returns True the seek
  fills and may advance again. A failed check on the initial seek
  reports nothing: the fill gate simply returns.

Unknowns, recorded explicitly (not modelled as facts): the identity of
0x5fe2680 and of its +0xa0 virtual's return; the +0x48 object's +0x28
subtrahend; the effect of the inner +0x50 virtual in the status-copy
code==0 reposition sequence (the model leaves the cursor unchanged
there); the inner iterator's Seek positioning (the model starts the
cursor at a caller-supplied index, default 0, and the outer loop does
the rest). The provider's varint-failure path is not pinned by this
window: the model raises ValueError there instead of claiming binary
behaviour.
"""

MASK64 = (1 << 64) - 1
HASH_SEED = 0xBC9F1D34
MASK_CONST = 0x9E3779B97F4A7C13

KNOWN_PREDICATE = 0x5F04DE0
KNOWN_STATUS_IMPL = 0x5F05680
STATUS_IMPL_GOT = 0x64ED790
KNOWN_PROVIDER = 0x5F05E10
PROVIDER_GOT = 0x64ED7B0
KNOWN_REPOSITION = 0x5F08320
REPOSITION_GOT = 0x64ED7D0
KNOWN_ADVANCE = 0x5F08470
ADVANCE_GOT = 0x64ED7D8
PERF_LEVEL_GOT = 0x64ED2B0
PERF_HELPER = 0x606DD10
TIMER_FACTORY = 0x5FE2680
TIMER_DESTROY = 0x5F05950
PROBE_HASH = 0x61C34A0
REFRESH = 0x5F08B00
READER = 0x5F07670
REPORTER = 0x5FCEDA0
VARINT = 0x61BD4F0
DETAIL_COPY = 0x61CF610


def ror12(value):
    """Rotate a 64-bit value right by 12."""
    return ((value >> 12) | ((value << 52) & MASK64)) & MASK64


def probe_base(count, hash32):
    """Base word index: (count * hash32) >> 32."""
    return (count * hash32) >> 32


def mask_bits(h64):
    """Two-bit mask positions of a (possibly rotated) hash value."""
    return (h64 & 63, (h64 >> 6) & 63)


def probe_passes(words, count, rounds, hash32):
    """Exact probe math of the 0x5f09050 prologue.

    words: the probe table (u64 words); count: table +0x0 (u32);
    rounds: table +0x4 (u32); hash32: the 0x61c34a0 result (32-bit,
    zero-extended to 64 bits, as the binary holds it in rax).
    Returns True on a hit, False on a miss. Round 0 is always tested,
    even when rounds is 0.
    """
    base = probe_base(count, hash32)
    h = (hash32 * MASK_CONST) & MASK64
    for k in range(max(rounds, 1)):
        b0, b1 = mask_bits(h)
        word = words[base ^ k]
        if not (word & (1 << b0)) or not (word & (1 << b1)):
            return False
        h = ror12(h)
    return True


def parse_length_prefix(buf):
    """Length-prefix parse of the inner +0x18 buffer.

    First byte below 0x80 is the length (slice starts one byte later);
    otherwise a bounded LEB128 varint at the buffer start (limit
    buf + 5, via 0x61bd4f0). Returns (length, slice_start_offset).
    Raises ValueError on a malformed varint (model guard; the binary's
    failure path here is not pinned by this window).
    """
    first = buf[0]
    if first < 0x80:
        return first, 1
    value = 0
    shift = 0
    for i in range(min(5, len(buf))):
        byte = buf[i]
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return value, i + 1
    raise ValueError("varint exceeds the 5-byte bound or runs past the buffer")


def _le_qword(buf, offset):
    return int.from_bytes(buf[offset:offset + 8], "little")


class SeekResult:
    def __init__(self, entry, ready, reports, perf_events, calls):
        self.entry = entry  # index the seek stopped at, or None
        self.ready = ready
        self.reports = reports  # list of (level, detail) report calls
        self.perf_events = perf_events  # counter offsets incremented
        self.calls = calls  # hook call log, in order


class MemtableIteratorSeekLoop:
    """The 0x5f09050 seek loop with injectable inner behaviour."""

    def __init__(self, entries, target, table=None, width=0,
                 perf_level=0, known_predicate=True,
                 predicate=None, refresh=None, reader=None,
                 provider=None, comparator=None, prefix_gate=None,
                 hash_fn=None, acquire=None, inner_start=0,
                 probe_subtrahend=0, reposition=None):
        self.entries = entries  # raw entry buffers: prefix + user key + trailer
        self.target = target  # target slice bytes (user key + trailer)
        self.table = table  # (words, count, rounds) or None
        self.width = width
        self.perf_level = perf_level
        self.known_predicate = known_predicate
        self.predicate = predicate  # unknown-predicate hook -> bool
        self.refresh = refresh  # hook(state) -> None, may set code
        self.reader = reader  # hook(buffer, width) -> code (0 ok)
        self.provider = provider  # hook(buffer) -> (offset, length)
        self.comparator = comparator  # hook(current_user, target_user) -> int
        self.prefix_gate = prefix_gate  # hook(probe_slice_len) -> bool
        self.hash_fn = hash_fn  # hook(ptr_len) -> hash int
        self.acquire = acquire  # hook(target) -> pointer-or-None
        self.reposition = reposition  # hook(state) -> None (+0x20 gate inline seq)
        self.pos = inner_start
        self.probe_subtrahend = probe_subtrahend
        self.ready = False
        self.code = 0
        self.sub = 0
        self.detail = None
        self.calls = []
        self.reports = []
        self.perf_events = []

    # -- hooks with binary defaults -------------------------------------
    def _predicate(self):
        if self.known_predicate:
            return self.ready and self.code == 0
        self.calls.append("predicate")
        return bool(self.predicate())

    def _fill_gate(self):
        """Fill gate; True means fill, False means return."""
        return self._predicate()

    def _fill(self):
        """Current slice (entry ptr offset, user length) for self.pos."""
        buf = self.entries[self.pos]
        if self.provider is not None:
            self.calls.append("provider")
            offset, length = self.provider(buf)
        else:
            length, offset = parse_length_prefix(buf)
        user_len = length - 8
        return offset, user_len

    def _compare(self, user_len, offset):
        buf = self.entries[self.pos]
        current = buf[offset:offset + user_len]
        target_user = self.target[:-8]
        if self.comparator is not None:
            self.calls.append("compare")
            return self.comparator(current, target_user)
        if current < target_user:
            return -1
        if current > target_user:
            return 1
        return 0

    def _advance(self):
        self.calls.append("next")
        self.pos += 1
        self.ready = self.pos < len(self.entries)

    def _run_reader(self):
        buf = self.entries[self.pos]
        self.calls.append("reader")
        code = self.reader(buf, self.width) if self.reader is not None else 0
        old_detail = self.detail
        self.code = code
        self.sub = 0
        self.detail = "check-detail" if code else None
        if old_detail is not None:
            self.calls.append("free-previous-detail")
        if code:
            self.calls.append("report")
            self.reports.append((3, self.detail))

    # -- main flow --------------------------------------------------------
    def run(self):
        if self.perf_level > 1:
            self.perf_events.append(0x140)
        timer = None
        if self.perf_level > 2 and self.acquire is not None:
            self.calls.append("acquire")
            timer = self.acquire(self.target)
        # Probe.
        if self.table is not None:
            gate = True
            if self.prefix_gate is not None:
                self.calls.append("prefix-gate")
                gate = self.prefix_gate(
                    len(self.target) - 8 - self.probe_subtrahend)
            if gate:
                words, count, rounds = self.table
                hash32 = self.hash_fn(len(self.target) - 8
                                      - self.probe_subtrahend) \
                    if self.hash_fn is not None else 0
                if probe_passes(words, count, rounds, hash32):
                    if self.perf_level > 1:
                        self.perf_events.append(0x200)
                else:
                    if self.perf_level > 1:
                        self.perf_events.append(0x208)
                    self.ready = False
                    if timer is not None:
                        self.calls.append("timer-destroy")
                    return SeekResult(None, self.ready, self.reports,
                                      self.perf_events, self.calls)
        # Inner seek + refresh.
        self.calls.append("inner-seek")
        self.ready = self.pos < len(self.entries)
        if self.refresh is not None:
            self.calls.append("refresh")
            self.refresh(self)
        # Predicate gate / status copy.
        if self.known_predicate:
            clean = self.ready and self.code == 0
        else:
            clean = self._predicate()
        if not clean:
            self.calls.append("status-copy")
            copy_code = self.code
            if copy_code != 0:
                self.calls.append("free-copy-detail")
            else:
                if self.reposition is not None:
                    self.calls.append("reposition")
                    self.reposition(self)
                self.calls.append("refresh")
                if self.refresh is not None:
                    self.refresh(self)
        # Fill gate (initial fill; no reader, no report here).
        if not self._fill_gate():
            if timer is not None:
                self.calls.append("timer-destroy")
            return SeekResult(None, self.ready, self.reports,
                              self.perf_events, self.calls)
        if self.pos >= len(self.entries):
            # Model guard: the binary's inner buffer past the end is not
            # pinned by this window, so a fill past the end is not run.
            if timer is not None:
                self.calls.append("timer-destroy")
            return SeekResult(None, self.ready, self.reports,
                              self.perf_events, self.calls)
        while True:
            if self.pos >= len(self.entries):
                break
            if self.perf_level > 1:
                self.perf_events.append(0x0)
            offset, user_len = self._fill()
            sign = self._compare(user_len, offset)
            if sign > 0:
                break
            if sign == 0:
                entry_trailer = _le_qword(self.entries[self.pos],
                                          offset + user_len)
                target_trailer = _le_qword(self.target, len(self.target) - 8)
                if entry_trailer >= target_trailer:
                    break
            # Advance.
            if self.perf_level > 1:
                self.perf_events.append(0x150)
            self._advance()
            if self.width:
                # Predicate re-gate on the advance path.
                gate_ok = self._predicate() if not self.known_predicate \
                    else (self.ready and self.code == 0)
                if gate_ok:
                    self._run_reader()
                # Rejoin the fill gate: a False first call re-enters it,
                # which calls the predicate a second time.
                if not self._fill_gate():
                    break
            else:
                if not self._fill_gate():
                    break
        if timer is not None:
            self.calls.append("timer-destroy")
        stopped = self.pos if self.pos < len(self.entries) else None
        return SeekResult(stopped, self.ready, self.reports,
                          self.perf_events, self.calls)
