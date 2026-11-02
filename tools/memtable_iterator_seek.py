"""Model of node #94's memtable iterator seek loop (window 0x5168a20).

RE-001 work item. The binary function is void: it positions an inner
iterator at a target internal key, optionally after a hash-table probe,
then loops: refresh, status snapshot, key-slice fill, compare, advance.
This model pins the loop's control flow and field effects exactly as
observed in research/work-items/RE-001-memtable-iterator-seek-94/; the
inner iterator's own Seek positioning, the hash callee, the comparator
implementation and the refresh handler internals are supplied as hooks,
because the window calls them through virtuals / by contract instead of
inlining them.

Binary facts (window 0x5168a20..0x5169220, 2048 bytes, FDE 0x1316ed0):
- Args: this (fields below) and a target key slice (ptr, len) whose last
  8 bytes are the trailer. The user key is the slice minus the trailer.
- this fields: +0x28 probe-table object or null, +0x30 prefix object,
  +0x48 comparator holder, +0x50 inner iterator, +0x58 ready flag,
  +0x60 check width, +0x68 installed code, +0x6c subcode, +0x70 detail
  string, +0x78 report context.
- Probe (skipped when +0x28 is null or the +0xa0 gate virtual is
  false): probe slice = (target ptr, target len - 8 - subtrahend), where
  the subtrahend is the +0x48 object's +0x28 word (identity unresolved).
  The +0x98 virtual's (ptr, len) return is hashed by 0x5422e70 with seed
  0xbc9f1d34. Base index = (hash * count) >> 32 with count = table +0x0
  (u32); each round r tests word table[base ^ r] against a two-bit mask
  from the hash: bits (hash & 63) and ((hash >> 6) & 63); a missing bit
  is a miss. The hash rotates right 12 (64-bit ror) each round; the loop
  runs table +0x4 (u32) rounds, but always tests at least the round-0
  word. Miss: ready = False and the function returns. Hit: continue.
- Inner seek: inner +0x30 virtual with the target, then inner +0x10
  virtual, stored to ready. Then the refresh handler 0x51684d0 runs.
- Predicate gate (vtable +0x10 vs known 0x51647b0): known means ready
  nonzero AND code zero; unknown calls the +0x10 virtual. When the gate
  does NOT take the clean path (known with ready False or code set, or
  unknown returning True), the status copy runs: the installed record
  (code, sub, detail) is copied to a stack record -- the vtable +0x68
  slot is a Status() virtual called with (record out-pointer, this)
  when it differs from the known implementation 0x5165050 (GOT
  0x57783d8), otherwise the copy is inlined, deep-copying the detail
  string. Copy code nonzero: the copy's detail is freed and the flow
  rejoins the fill gate. Copy code zero: the +0x20 gate runs (any slot
  other than the cf0 handler from GOT 0x5778418 is called with this;
  the cf0 flavor instead runs the inline sequence: inner +0x50
  virtual, inner +0x10 valid stored to ready, refresh 0x51684d0) and
  the flow rejoins the fill gate.
- Fill gate: known predicate re-checks ready AND code == 0, else return;
  unknown predicate is called again (a second call) and must be True,
  else return. Fill: the key provider gate (vtable +0x50 vs the default
  provider 0x51657e0 from GOT 0x57783f8) inlines the length-prefix parse
  of the inner +0x18 buffer, otherwise calls the +0x50 virtual; the
  current slice is (entry ptr, parsed length - 8).
- Compare: the +0x10 virtual of the +0x48 object's +0x20 subobject is
  called with the target and current slices; observed sign-to-action
  mapping: positive stops the seek, zero falls to the trailer check,
  negative advances. Trailer check (only on a zero compare): the entry
  trailer qword (8 bytes at entry + user length) vs the target trailer
  qword (last 8 bytes of the target), unsigned; entry trailer below the
  target trailer advances, otherwise the seek stops.
- Advance: the +0x48 gate (vtable +0x48 vs the e40 handler from GOT
  0x5778420) inlines inner +0x28 (next) then inner +0x10 (valid -> ready)
  for the known flavor, otherwise calls the +0x48 virtual. Then, when
  width is nonzero, the predicate gate runs again (known: ready and
  code == 0; unknown: call, and a False first call re-enters the fill
  gate, which calls the predicate a second time). On a passing gate the
  entry check 0x5167040 runs as reader(record, buffer, width, 0) and its
  code/sub/detail install to +0x68/+0x6c/+0x70, freeing the previous
  detail with array delete after the install. A nonzero installed code
  reports via 0x522e770 at level 3 (context +0x78, format
  "[%s:538] In MemtableIterator: %s", file "db/memtable.cc", detail
  +0x70) and rejoins the fill gate -- which, for the known predicate,
  returns at once because the code is still set, while for an unknown
  predicate that still returns True the seek fills and may advance
  again. A failed check on the initial seek (before any advance)
  reports nothing: the fill gate simply returns.
- Perf: the entry call to 0x52cd6e0 is unconditional; when the TLS perf
  byte exceeds 1, further helper calls increment counters at TLS-0x350
  offsets +0x140 (entry path), +0x200 (probe hit), +0x208 (probe miss),
  +0x0 (fill path) and +0x150 (advance path). When the perf byte
  exceeds 2 at entry, the 0x5242050 prologue runs and its acquired
  pointer is destroyed via 0x5165320 on exit when non-null.

Unknowns, recorded explicitly (not modelled as facts): the identity of
0x5242050 and of its +0xa0 virtual's return; the +0x48 object's +0x28
subtrahend; the effect of the inner +0x50 virtual in the status-copy
code==0 reposition sequence (the model leaves the cursor unchanged
there); the inner iterator's Seek positioning (the model starts the
cursor at a caller-supplied index, default 0, and the outer loop does
the rest).
The provider's varint-failure path is not pinned by this window: the
model raises ValueError there instead of claiming binary behaviour.
"""

MASK64 = (1 << 64) - 1


def ror64(value, bits):
    return ((value >> bits) | (value << (64 - bits))) & MASK64


def probe_passes(table_words, count, rounds, hash_value):
    """Exact probe math of the 0x5168a20 prologue.

    table_words: the probe table (u64 words); count: table +0x0 (u32);
    rounds: table +0x4 (u32); hash_value: the 0x5422e70 result (32-bit,
    zero-extended to 64 bits, as the binary holds it in rax).
    Returns True on a hit, False on a miss.
    """
    h = hash_value & MASK64
    base = ((h * count) & MASK64) >> 32
    r = 0
    while True:
        word = table_words[base ^ r]
        mask = (1 << (h & 63)) | (1 << ((h >> 6) & 63))
        if mask & ~word & MASK64:
            return False
        r += 1
        if r >= rounds and rounds != 0:
            return True
        if rounds == 0:
            # The loop always tests the round-0 word, then stops: with
            # rounds == 0 the round-0 check above already decided.
            return True
        h = ror64(h, 12)


def parse_length_prefix(buf):
    """Length-prefix parse shared by the entry check and the provider.

    First byte below 0x80 is the length (slice starts one byte later);
    otherwise a bounded LEB128 varint at the buffer start (limit
    buf + 5). Returns (length, slice_start_offset). Raises ValueError
    on a malformed varint (model guard; the binary's failure path here
    is not pinned by this window).
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
        self.entry = entry  # the entry the seek stopped at, or None
        self.ready = ready
        self.reports = reports  # list of (level, detail) report calls
        self.perf_events = perf_events  # counter offsets incremented
        self.calls = calls  # hook call log, in order


class MemtableIteratorSeek:
    """The 0x5168a20 seek loop with injectable inner behaviour."""

    def __init__(self, entries, target, table=None, width=0,
                 perf_level=0, known_predicate=True,
                 predicate=None, refresh=None, reader=None,
                 provider=None, comparator=None, prefix_gate=None,
                 hash_fn=None, acquire=None, inner_start=0,
                 probe_subtrahend=0):
        self.entries = entries  # list of entry buffers (user key + trailer)
        self.target = target
        self.table = table  # (words, count, rounds) or None
        self.width = width
        self.perf_level = perf_level
        self.known_predicate = known_predicate
        self.predicate = predicate  # unknown-predicate hook -> bool
        self.refresh = refresh  # hook(state) -> None, may set code
        self.reader = reader  # hook(buffer, width) -> code (0 ok)
        self.provider = provider  # hook(buffer) -> (ptr_offset, length)
        self.comparator = comparator  # hook(current_user, target_user) -> int
        self.prefix_gate = prefix_gate  # hook(probe_slice) -> bool
        self.hash_fn = hash_fn  # hook(ptr, len) -> hash int
        self.acquire = acquire  # hook(target) -> pointer-or-None
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

    def _refresh(self):
        self.calls.append("refresh")
        if self.refresh is not None:
            self.refresh(self)

    def _reader(self, buf):
        self.calls.append("reader")
        if self.reader is None:
            return 0
        return self.reader(buf, self.width)

    def _provider_slice(self, buf):
        # Returns (slice_start_offset, length). parse_length_prefix
        # returns (length, slice_start_offset), so swap its result.
        if self.provider is not None:
            self.calls.append("provider")
            return self.provider(buf)
        length, off = parse_length_prefix(buf)
        return off, length

    def _compare(self, current_user, target_user):
        if self.comparator is not None:
            return self.comparator(current_user, target_user)
        if current_user < target_user:
            return -1
        if current_user > target_user:
            return 1
        return 0

    def _snapshot(self):
        # Status copy: copy (code, sub, detail). Copy code nonzero
        # frees the copy's detail. Copy code zero runs the +0x20 gate
        # and, for the cf0 flavor, the inline reposition sequence:
        # inner +0x50 virtual, inner valid stored to ready, refresh.
        self.calls.append("snapshot")
        snap_code = self.code
        if snap_code != 0:
            self.calls.append("snapshot_detail_freed")
            return
        self.calls.append("gate_0x20")
        self.calls.append("inner_reposition")
        self.ready = bool(self.entries) and self.pos < len(self.entries)
        self._refresh()

    def _fill_gate(self):
        # Returns True when the fill may proceed, False to return.
        if self.known_predicate:
            return self.ready and self.code == 0
        return self._predicate()

    # -- the seek --------------------------------------------------------
    def seek(self):
        acquired = None
        if self.perf_level > 2 and self.acquire is not None:
            acquired = self.acquire(self.target)
            self.calls.append("acquire")
        if self.perf_level > 1:
            self.perf_events.append(0x140)
        target_user = self.target[:-8]
        target_trailer = _le_qword(self.target, len(self.target) - 8)

        def finish(entry):
            if acquired is not None:
                self.calls.append("temp_destroyed")
            return SeekResult(entry, self.ready, self.reports,
                              self.perf_events, self.calls)

        # Probe phase.
        if self.table is not None:
            probe_len = len(self.target) - 8 - self.probe_subtrahend
            probe_slice = self.target[:probe_len]
            gate = True if self.prefix_gate is None else self.prefix_gate(probe_slice)
            if gate:
                words, count, rounds = self.table
                h = 0 if self.hash_fn is None else self.hash_fn(probe_slice)
                if not probe_passes(words, count, rounds, h):
                    self.ready = False
                    if self.perf_level > 1:
                        self.perf_events.append(0x208)
                    return finish(None)
                if self.perf_level > 1:
                    self.perf_events.append(0x200)

        # Inner seek + refresh.
        self.calls.append("inner_seek")
        self.ready = bool(self.entries) and self.pos < len(self.entries)
        self._refresh()

        # Predicate gate / snapshot / fill gate (initial path). Known
        # clean goes straight to the fill; known unclean and unknown
        # True take the snapshot first; unknown False goes straight to
        # the fill gate, which calls the predicate a second time.
        if self.known_predicate:
            if not (self.ready and self.code == 0):
                self._snapshot()
                if not self._fill_gate():
                    return finish(None)
        else:
            if self._predicate():
                self._snapshot()
            if not self._fill_gate():
                return finish(None)

        # Fill / compare / advance loop. Every fill after an advance is
        # preceded by a fill-gate evaluation (the f59/d49 rejoin), so
        # the advance block below always ends in a _fill_gate call.
        while True:
            if not self.ready or self.pos >= len(self.entries):
                return finish(None)
            buf = self.entries[self.pos]
            off, length = self._provider_slice(buf)
            current_user = buf[off:off + length - 8]
            if self.perf_level > 1:
                self.perf_events.append(0x0)
            cmp_result = self._compare(current_user, target_user)
            if cmp_result > 0:
                break
            if cmp_result == 0:
                entry_trailer = _le_qword(buf, off + length - 8)
                if entry_trailer >= target_trailer:
                    break
            # Advance: inner next + valid, then (width != 0) the
            # predicate gate and the reader check; every advance path
            # rejoins the fill gate before the next fill.
            self.calls.append("advance")
            self.pos += 1
            self.ready = self.pos < len(self.entries)
            if self.perf_level > 1:
                self.perf_events.append(0x150)
            if self.width != 0:
                if self.known_predicate:
                    gate_ok = self.ready and self.code == 0
                else:
                    gate_ok = self._predicate()
                if gate_ok:
                    code = self._reader(buf)
                    old_detail = self.detail
                    self.code = code
                    self.detail = None if code == 0 else "check failed"
                    if old_detail is not None:
                        self.calls.append("old_detail_freed")
                    if code != 0:
                        self.reports.append((3, self.detail))
            if not self._fill_gate():
                return finish(None)

        return finish(self.entries[self.pos])
