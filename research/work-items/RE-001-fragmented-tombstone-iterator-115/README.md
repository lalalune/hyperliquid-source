# RE-001: node #115's FragmentedRangeTombstoneIterator

## Bounded question

How does node #115's `FragmentedRangeTombstoneIterator` work end to
end — how it seeks, scans, steps and builds keys over a fragmented
range-tombstone list, and what `MaxCoveringTombstoneSeqnum` returns
for a key? The answer is one complete behaviour: the full 24-slot
method family around `0x5f32900`, its 0xc8-byte layout, its two
constructors (by contract from open PR #3674), its comparator
dispatch, and its destructor.

This packet resolves open PR #3674's open unknown "the iterator
vtable and its methods" and corrects three of its labels: the cache
shared_ptr sits at +0x58/+0x60 (not +0x48/+0x50 — the ctor-B excerpt
and #3674's records prove it), the GOT slot 0x64ecfa0 points at
`FSRandomAccessFileWrapper::Read` (not at comparator dispatch), and
the upper-bound clamp's search goes left when the comparison is
<= 0 (it finds the first entry whose comparison is <= 0, not the
first entry > 0 — the builtin short-circuit leaves consumed = 0).

## Answer (pinned)

- **Layout** (0xc8 bytes): +0x00 vtable `0x64ccae0+0x10` (24 slots,
  typeinfo `N7rocksdb32FragmentedRangeTombstoneIteratorE`); +0x08
  Cleanable; +0x28/+0x30 = icmp+0x8; +0x38 = icmp pointer; +0x40 =
  icmp+0x8 (P, the user-comparator object); +0x48/+0x50 = a second
  shared_ptr (null from both ctors; the dtor releases it when
  non-null; what sets it is open); +0x58/+0x60 = the cache
  shared_ptr (null in ctor A; the copy in ctor B); +0x68 list/cache
  pointer; +0x70 read seq; +0x78 arg6 (the visibility threshold:
  visible when `*seq >= arg6`); +0x80 upper_bound Slice*; +0x88
  current fragment; +0x90 current seqnum pointer; +0x98/+0xa0
  shadow copies; +0xa8..+0xc8 cached-key std::string (data ptr,
  size, 16-byte inline buffer; heap when len > 15).
- **Fragment** (0x30): +0x00/+0x08 start-key Slice; +0x10/+0x18
  end-key Slice; +0x20 seq_idx_begin; +0x28 seq_idx_end.
  **List**: +0x00 frag_begin; +0x08 frag_end; +0x10 unknown;
  +0x18 seq-array base; +0x20 seq-array end; +0x28 unknown; +0x30
  key-array base (16-byte Slice entries, one per seqnum).
  Seqnums are sorted DESCENDING within each fragment's range; the
  search finds the first element <= read seq.
- **Vtable** (24 slots): [0] ~D1 `0x5f32a10`, [1] ~D0 `0x5f32b80`,
  [2] Valid `0x5f2e8f0`, [3] SeekToFirst `0x5f2e8d0`, [4] SeekToLast
  `0x5f2ee70`, [5] Seek `0x5f320a0`, [6] SeekForPrev `0x5f324f0`,
  [7] Next `0x5f2eea0`, [8] NextAndGetResult `0x5df7ce0`, [9] Prev
  `0x5f2eef0`, [10] key `0x5eba980`, [11] slot-11 accessor
  `0x5df7650` (key minus the 8-byte trailer; C++ name open), [12]
  value `0x5eba910` (the fragment end key), [13] status `0x5f2e7b0`
  (OK), [14]-[16] bool getters (1, 1, 0), [17] void no-op, [18]
  bool getter 0, [19] bool getter 1, [20] Status builder
  `0x5df7800`, [21]-[22] void no-ops, [23] bool getter 0. Slots
  [11], [14]-[17], [20]-[23] are SHARED with MemTableIterator's
  vtable (`0x64cc638+0x10`, typeinfo
  `N7rocksdb16MemTableIteratorE`); MemTableIterator differs at [8]
  (`0x5f08790`), [10] (`0x5f05e10`), [12] (`0x5f05e80`), [13]
  (`0x5f05680`), [18] (`0x5f04e00`), [19] (`0x5f04e10`).
- **SeekToCoveringTombstone** (`0x5f316d0`, 675 B): phase 1 binary
  search over fragments by END key via slot 0xd0 for the first
  fragment with end > key; phase 2 descending-seqnum search for
  the first seq <= read seq; phase 3 upper-bound clamp; empty list
  -> (frag_end, seq_end). Does NOT touch the shadow.
  **SeekForPrevToCoveringTombstone** (`0x5f31980`, 765 B): the same,
  but phase 1 compares (key, frag START key) for the first fragment
  with start > key, then steps back one (the last fragment with
  start <= key); empty list -> (frag_end, seq_end); no covering
  fragment -> (frag_end, seq_base).
- **ScanForward** (`0x5f31c80`, 557 B) / **ScanBackward**
  (`0x5f320f0`, 539 B): loop — frag == end -> return; seq_ptr ==
  range end -> advance to the next/previous fragment (re-search
  seqnums + clamp; at the last/first fragment -> (frag_end,
  seq_end)); `*seq >= arg6` -> return (visible); else advance.
  **SeekToTopFirst** (`0x5f31eb0`) / **SeekToTopLast** (`0x5f32310`):
  first/last fragment + seq search + clamp, then tail-jump to the
  matching scan; empty -> (frag_end, seq_end).
  **Seek** (`0x5f320a0`) / **SeekForPrev** (`0x5f324f0`): empty ->
  (frag_end, seq_end); else the covering seek + tail-jump to the
  matching scan. The two are the same 65-byte shape with different
  callees; the catalogue lists them as one of 2 identical copies.
- **TopNext** (`0x5f32540`): frag += 0x30; at end -> return leaving
  the seq pointer as-is; else seq search over the new fragment's
  range (read via the old frag's +0x50/+0x58) + clamp + tail-jump
  ScanForward. **TopPrev** (`0x5f32720`): at the first fragment ->
  (frag_end, seq_base) — differs from Prev's (frag_end, seq_end);
  else frag -= 0x30 + seq search + clamp + tail-jump ScanBackward.
- **Valid** (`0x5f2e8f0`, 30 B): `(list != null) &&
  (*(list+0x8) != +0x88)`. **SeekToFirst** (`0x5f2e8d0`, 25 B):
  frag = first, seq = seq base. **SeekToLast** (`0x5f2ee70`,
  34 B): paddq constant at 0x4535e0 = (-48, -8) -> frag = frag_end
  - 0x30, seq = seq_end - 8. **Next** (`0x5f2eea0`, 68 B): +0x90 +=
  8; at range end -> +0x88 += 0x30; no shadow update. **Prev**
  (`0x5f2eef0`, 112 B): seq_ptr == seq base -> (frag_end, seq_end)
  WITH shadow update; else +0x90 -= 8; crossing fragment start ->
  +0x88 -= 0x30; from the end position -> the last fragment's last
  seqnum.
- **key()** (`0x5eba980`, 212 B): if frag == end -> return cached;
  if seq_ptr == seq-array end -> return cached; if (frag,seq) ==
  shadow -> return cached; else rebuild: clear the cached string,
  build a 25-byte `ParsedInternalKey` on the stack (start-key
  Slice, seqnum, type byte 0x0f), call `AppendInternalKey`
  `0x5eaa060` (catalogue-confirmed), set shadow = current position,
  return (cached data, cached size). Cached key = fragment start
  key + PackSequenceAndType(seq, 0x0f) = (seq<<8)|0x0f little-endian.
  At the end position key() returns the STALE cached key (empty on
  a fresh iterator). Stack canary checked.
- **Shadow semantics**: the shadow is written ONLY by key() itself
  (after rebuilding), the ctors, and the end-position movups pairs.
  The seek/scan/top normal paths and Next/Prev do NOT update it
  (plain qword stores to +0x88/+0x90), so key() rebuilds after any
  of them moves the iterator.
- **Two end variants**: (frag_end, seq_end) vs (frag_end, seq_base);
  both invalid, but key() and MaxCoveringTombstoneSeqnum read the
  seq pointer. TopNext at the last fragment leaves the seq pointer
  as-is.
- **MaxCoveringTombstoneSeqnum** (`0x5f32900`, 266 B): call
  SeekToCoveringTombstone; Valid check (devirtualized: vtable slot
  0x10 == 0x5f2e8f0); return 0 if invalid, if seq_ptr == fragment
  range end, or if fragment start key > key (compare via slot
  0xd0); else return `*(+0x90)`. Callers: two MemTable lookup/Get
  paths (`0x5f0d050`, `0x5f0d740`), `TableCache::
  UpdateRangeTombstoneSeqnums` (`0x5f3d4f0`), `TableCache::Get`
  (`0x5f40070`) — see `callers.tsv`.
- **NextAndGetResult** (`0x5df7ce0`, 68 B, shared
  `InternalIteratorBase<Slice>` impl): call vtable slot 0x38
  (Next), slot 0x10 (Valid); if valid, slot 0x50 (key) into
  result+0x0/+0x8 and u16 0 at result+0x10; return Valid.
  **Slot 11** (`0x5df7650`, 23 B): returns key() with len-8 (the
  user key); C++ name open. **value()**: fragment end-key Slice.
  **status()**: OK (16-byte zero).
- **Dtor** (`0x5f32a10` D1, `0x5f32b80` D0): reset vtable; free the
  key-cache heap buffer iff data ptr != inline buffer (`operator
  delete(ptr, capacity+1)`); release the +0x60 ctrl (cache
  shared_ptr) then the +0x50 ctrl (second slot) via `_M_release`
  (packed 0x100000001 fast dispose, else the 0x64ed290-selector
  decrement, dispose via 0x5d35070 at count 0); reset vtable to base
  `0x64ca800+0x10`; Cleanable::DoCleanup `0x61bd0e0` (D1 tail-jumps,
  D0 calls then `operator delete(this, 0xc8)`).
- **Comparator dispatch**: P = this+0x40 = icmp+0x8. Slot 0xc8 (25)
  = CompareTimestamp (best-supported reading): called as
  compare(entry, upper_bound); builtin impl `0x5d48400` (`xor
  eax,eax; ret`) returns 0. Slot 0xd0 (26) =
  CompareWithoutTimestamp (catalogue-confirmed): Bytewise impl
  `0x61bdc40` (plain memcmp ignoring the bool flags), Reverse impl
  `0x61bdc90` (negated memcmp, reversed length tiebreak). Both
  vtables have 29 slots (base Bytewise `0x64d7028`, stored
  `0x64d7038`, typeinfo `*N7rocksdb12_GLOBAL__N_1
  22BytewiseComparatorImplE`; Reverse base `0x64d7148`, stored
  `0x64d7158`, typeinfo `*N7rocksdb12_GLOBAL__N_1
  29ReverseBytewiseComparatorImplE` — the leading `*` is the literal
  first byte of the stored name string). GOT slots: 0x64ecfa8 ->
  0x5d48400, 0x64ecfb0 -> 0x5d48410 (the slot-0xd0 fast-path thunk,
  forwards to *(P+0x20)->vtable[0x10]). 0x64ecfa0 -> 0x5d44c70 is
  NOT comparator dispatch — 0x5d44c70 is catalogue-confirmed
  `FSRandomAccessFileWrapper::Read`, a neighbouring GOT slot no
  family function references. The identity of Q = *(P+0x20) and of
  Q->vtable[0x10] remains open.
- **Seq search** (shared by the 8 seek/scan/top functions): binary
  search on the descending array for the first seq <= read seq, or
  the range end; read_seq >= *mid (jae) keeps the left half, else
  the base advances past mid.
- **Upper-bound clamp** (shared by the same 8): binary search the
  key array for the first entry with CompareTimestamp(entry, ub)
  <= 0 — the loop goes left when the comparison is <= 0 and right
  when it is > 0, so it assumes the key array is sorted with the
  comparison decreasing in the entry index; consumed = that entry's
  index within the range; if the current seq offset < consumed,
  seq_ptr = seq_base + (begin+consumed)*8. With the builtin
  comparators the search short-circuits before any comparison
  (consumed = 0), so the clamp is a no-op; a timestamped comparator
  makes the clamp cut the visible seq window at the first key-array
  entry whose timestamp comparison is <= 0.

## Evidence

- `records.json`: semantic records only (no per-instruction mnemonic
  list). Instruction-level detail lives in the raw disassembly
  excerpts below, kept verbatim and whole-function. Mnemonics such
  as `endbr64` are genuine instructions present in the target binary,
  not placeholders.
- Whole-function verbatim excerpts (`*.objdump.txt`, regenerated by
  `export_excerpts.py`): all 33 windows, from `objdump -d` on the
  digest-verified binary (GNU objdump 2.42). The excerpts are
  generated per FDE range, so each file is exactly one function.
- `frames.txt`: the 33 FDE blocks from `objdump --dwarf=frames`.
- `callers.tsv`: every census site with its containing FDE and role
  (86 rows: 27 family sites + 59 `AppendInternalKey` sites, each
  confirmed as a real call/jump in its FDE). The generic helpers
  (Cleanable::DoCleanup, `_M_release` dispose, Cleanable ctor) are
  libstdc++/RocksDB-wide with 223+32 / 654+36 / 103 call sites; their
  full caller lists add no RE value, so the packet pins only the
  sites this behaviour uses (`packet_internal_sites` in
  `records.json`: 2 + 2 + 3 sites, each verified in its FDE).
- `vtables.tsv`: the four vtables resolved through
  R_X86_64_RELATIVE entries — typeinfo names and every slot target
  (FragmentedRangeTombstoneIterator 24 slots, MemTableIterator 24,
  BytewiseComparatorImpl 29, ReverseBytewiseComparatorImpl 29).
- `relocations.txt`: the RELATIVE entries pointing at a packet
  window or census target are exactly the vtable/GOT slots recorded
  in `records.json`; the comparator GOT slots and the typeinfo `*`
  quirk are explained there.
- `verify.py`: the packet checker — run it from the repo root. It
  re-derives the excerpts, byte-checks fixed samples plus 3 seeded
  random gate spots against a fresh objdump run and the raw binary,
  re-runs the census, verifies every census site and every
  in-packet generic-helper site in its FDE, re-checks the vtable
  resolutions and the RELATIVE slot set, and runs the model tests.
- `census.py` / `export_excerpts.py` / `gen_records.py`: regenerate
  the census, the excerpts and `records.json` from the binary.
- Overlap note: open PR #3433 (mapmapdown, RE-002) identifies the
  same 24-slot vtable (0x64ccaf0) with its stores; this packet
  re-derives the slot map independently through the
  R_X86_64_RELATIVE slot-owner walk as supporting evidence for the
  method family, and the 33 method excerpts, the behaviour, the
  model and the tests are new here. Open PR #3066 (mapmapdown,
  RE-002) maps the range-tombstone aggregation transfers; this
  packet cites the aggregation FDEs only as TopNext/TopPrev caller
  sites in the census (their identities are given by the calls they
  make), not as a work item.

## Model and tests

- `tools/fragmented_tombstone_iterator_115.py`: the Python model
  (Bytewise / ReverseBytewise / Timestamped comparators, Fragment,
  FragmentList with the descending-seqnum assertion, SharedPtr,
  the full iterator with all methods above, the two end variants,
  the shadow updated only by key() rebuilds and the Prev array-base
  path, `destroy(delete_self=False/True)` with trace).
- `tests/test_fragmented_tombstone_iterator_115.py`: 219 checks, all
  passing, including the binary searches cross-checked against
  independent linear-scan references on seeded random inputs, the
  clamp cross-checked against the brute-force first-<=0 index on
  descending key arrays, seek/seek_for_prev against a linear-scan
  reference on 30 random lists, and key()/value()/status()/slot11
  and the dtor traces.

## Bound to

- Artifact `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (`provenance/artifacts.json`).
- Binary `work/hl-node-115.bin` (same digest, verified by `verify.py`).

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so `make
verify` / `make test` / `make catalogue-check` could not be run here;
the packet's own `verify.py` and the model tests are the checks that
were run. The vendor attributions are the catalogue's
relocation-qualified matches (e.g. MaxCoveringTombstoneSeqnum
266/266, key() 212/212), not this packet's own rebuilds. The
constructors (0x5f31380, 0x5f315a0) and the cache ctor are #3674's
contract, cited here rather than re-shipped; the tiny shared stubs
and the slot-11 accessor are identified by shape, not by a catalogue
row. GNU objdump (Binutils) 2.42 was used for all disassembly.

## Open unknowns

See `records.json` `unknowns`: the C++ names for vtable slots [11],
[14]-[23]; the IterateResult layout beyond key + u16 0; the identity
of P's +0x20 subobject Q and of the thunk's target Q->vtable[0x10];
how icmp+0x8 holds a Comparator* when InternalKeyComparator is 8
bytes; the exact C++ name of comparator slot 0xc8; the semantic
identity of the key-array entries (end keys vs timestamp keys);
list+0x10 and list+0x28; what sets the second shared_ptr at
+0x48/+0x50; the +0x78 arg6 threshold's source-level identity; the
no-catalogue-row MemTable lookup/Get and MergingIterator caller FDEs;
the cache struct layout behind ctor B; the landing-pad / LSDA tables.
