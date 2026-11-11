# RE-001: pin the InternalIterator vtable tail slots [11], [14]-[23] (node #115)

## Task and bounded question

Task ID: **RE-001**. Question: what are the C++ names and behaviours of
the `InternalIteratorBase<Slice>` vtable tail slots **[11]** and
**[14]-[23]** in node #115, and how does each of the 21 iterator classes
in the binary implement them?

This resolves the open unknown left by #3900 ("the C++ names for vtable
slots [11], [14]-[23]" of the FragmentedRangeTombstoneIterator /
MemTableIterator family) by pinning the whole tail for every
InternalIterator class in the binary, not just one family.

## Method

The binary is `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`). The
embedded RocksDB is v8.1.1 (string `rocksdb_build_git_tag:v8.1.1`).

`.data.rel.ro` is zero-filled in the file, so every vtable slot value
comes from a `.rela.dyn` R_X86_64_RELATIVE entry. Scanning those
entries (file offset `0x6BE8`, 59,534 entries) for the nine shared
tail stubs and back-computing each vtable's stored pointer enumerates
**21 real InternalIterator vtables** (plus 5 false positives with no
typeinfo, excluded in `records.json`). The typeinfo pointer
(stored_ptr - 8) names each class. See `census.py`.

Slot identities are pinned three ways: (1) the whole-function bodies
in `excerpts/` (GNU objdump 2.42, `objdump -d --start-address=<start>
--stop-address=<end> work/hl-node-115.bin`, FDE ranges from
`objdump --dwarf=frames`); (2) the RocksDB v8.1.1 headers
(`table/internal_iterator.h`,
`table/block_based/block_based_table_iterator.h`,
`db/forward_iterator.h`) and the `IteratorWrapperBase` calls in
`table/iterator_wrapper.h`, which match the binary bodies exactly
where they overlap (BlockBasedTableIterator `PrepareValue`,
`UpperBoundCheckResult`, `IsKeyPinned`, `IsValuePinned`, `user_key`,
`GetReadaheadState`, `SetReadaheadState`); (3) a dispatch-site census
(`callers.tsv`): 1,719 verified indirect call/jmp sites through the
tail offsets, of which 132 survive the iterator-consumer filter (the
containing FDE must dispatch through `Valid` 0x10 and `key` 0x50 plus
at least two more core InternalIterator slots -- offsets 0x98/0xa0/0xb0
are shared with other hierarchies, so the core-slot bar is what
separates a real InternalIterator dispatch from a same-offset dispatch
through another class's vtable).

Mnemonics such as `endbr64` are genuine instructions present in the
target binary, not placeholders. Instruction-level detail lives only
in the raw excerpts; `records.json` carries semantic records.

## Slot map

| slot | offset | C++ name | default (base class) |
| --- | --- | --- | --- |
| 11 | 0x58 | `user_key()` | `key()` with 8 bytes stripped |
| 14 | 0x70 | `PrepareValue()` | `true` |
| 15 | 0x78 | `MayBeOutOfUpperBound()` | `true` |
| 16 | 0x80 | `UpperBoundCheckResult()` | `kUnknown` (0) |
| 17 | 0x88 | `SetPinnedItersMgr(PinnedIteratorsManager*)` | no-op |
| 18 | 0x90 | `IsKeyPinned()` | `false` |
| 19 | 0x98 | `IsValuePinned()` | `false` |
| 20 | 0xa0 | `GetProperty(std::string, std::string*)` | `Status::NotSupported` (code 3) |
| 21 | 0xa8 | `GetReadaheadState(ReadaheadFileInfo*)` | no-op |
| 22 | 0xb0 | `SetReadaheadState(ReadaheadFileInfo*)` | no-op |
| 23 | 0xb8 | `IsDeleteRangeSentinelKey()` | `false` |

`IterBoundCheck`: `kUnknown = 0`, `kOutOfBound = 1`, `kInbound = 2`
(read off BlockBasedTableIterator [16]: `is_out_of_bound_` -> 1,
`block_upper_bound_check_ == kUpperBoundBeyondCurBlock` -> 2, else 0;
`BlockUpperBound`: `kUpperBoundInCurBlock = 0`,
`kUpperBoundBeyondCurBlock = 1`, `kUnknown = 2`).

The 21 classes (mangled typeinfo names; the leading `*` on the three
anonymous-namespace classes -- LevelIterator, EmptyInternalIterator,
TruncatedRangeDelMergingIter -- is verbatim from the binary's
typeinfo name strings): InternalIteratorBase, BlobCountingIterator,
ClippingIterator, HistoryTrimmingIterator, SequenceIterWrapper,
ForwardLevelIterator, ForwardIterator, MemTableIterator,
TruncatedRangeDelMergingIter, VectorIterator,
FragmentedRangeTombstoneIterator, LevelIterator, BlockIter,
DataBlockIter, MetaBlockIter, BlockBasedTableIterator,
CuckooTableIterator, EmptyInternalIterator, MergingIterator,
CompactionMergingIterator, PlainTableIterator. Full per-class table in
`vtables.tsv` (231 rows).

### Notable behaviours (see `records.json` for all 78 windows)

- **Wrappers delegate.** BlobCountingIterator delegates every tail
  slot to its inner iterator (+0x28); ClippingIterator delegates
  [11]/[17]/[18]/[19]/[23] and its [20] copies `prop_name` before
  forwarding; HistoryTrimmingIterator delegates only [18]/[19]/[23];
  SequenceIterWrapper delegates [23] to its wrapped iterator (+0x38).
- **PrepareValue caches.** MergingIterator [14] asks the current
  child once, caches the result in the wrapper's +0x19 flag, and on
  failure copies the child's `status()` (slot [13]) into +0xb8/+0xba/
  +0xc0. LevelIterator [14] caches via its +0xc9 flag. ForwardIterator
  [14] copies the child status into +0x178/+0x17c/+0x180 on failure.
  CompactionMergingIterator [14] always returns false.
- **Pinning is manager-gated.** Every mgr-gated [18]/[19] returns
  false when the manager is null or its +0x20 byte (pinning-enabled)
  is clear, and only then delegates. BlockBasedTableIterator [18] at
  the first key from the index calls the index iterator's
  `IsValuePinned`; otherwise it inlines BlockIter [18]
  (`+0x109 ? +0x108 : 0`, gated by
  `block_iter_points_to_real_block_`); [19] is just that flag.
  MemTableIterator [18] is always true; FragmentedRangeTombstone-
  Iterator [18] is always false (its `key()` rebuilds into a cached
  string) and [19] always true.
- **GetProperty.** The base returns `NotSupported`. ForwardIterator
  [20] answers exactly one property,
  `rocksdb.iterator.super-version-number` (37 chars), with the decimal
  SuperVersion number (uint64 at SuperVersion+0x218); anything else is
  `InvalidArgument` (code 4).
- **Readahead.** Only BlockBasedTableIterator overrides [21]/[22]:
  [21] fills the output with the 16-byte Slice from the table holder
  and forwards to the index iterator unless it is the base stub;
  [22] copies the 16-byte Slice into +0x260 and forwards likewise.
- **Sentinel key.** LevelIterator [23] returns its +0xf8 flag
  (`is_delete_range_sentinel_key_`); CompactionMergingIterator [23]
  returns (child +0x50 == 1); CompactionIterator's `Next` (FDE
  0x5e2d590) caches the [23] result at +0x448 and branches on it.
- **ClippingIterator** is the only class that overrides [15] with
  `false` and [16] with `kInbound` (2): a clipped range can never be
  out of the upper bound.

## What this does not claim

- The 8.1.1 interface has exactly one `MayBe*` slot ([15]); there is
  **no `MayBeOutOfLowerBound` slot** in this binary -- that method
  appears only in later RocksDB releases' `IteratorWrapperBase`.
- Slot [13] is `status()` (returns `Status` by value, hidden sret
  pointer in `rdi`); it is outside the tail range but is called by the
  ForwardIterator and MergingIterator `PrepareValue` false paths.
- The `IterateResult` layout beyond `key` (Slice at +0) plus a zero
  u16 at +0x10 remains open (carried from #3900).
- MemTableIterator [19] reads the byte at +0x5a; its exact
  construction-flag meaning is open (see #3803).
- The CompactionMergingIterator child +0x50 flag's source identity is
  open; only its observed effect is recorded.
- BlockIter +0x108/+0x109 member names are not pinned; only the
  observed byte semantics are recorded.
- BlockIter vtable slots [0]/[1] (dtors) and [12] (`value`) have no
  relocations and zero file bytes; [12] is a type-1 relocation to
  `__cxa_pure_virtual`. Not chased here.

## Files

- `records.json` -- semantic records only (slot map, enums, vtable
  census, 78 window behaviours, field notes, property, dispatch
  summary). No per-instruction mnemonic list.
- `vtables.tsv` -- the 21 vtables x tail slots (231 rows).
- `excerpts/` -- 80 whole-function verbatim objdump excerpts (78 tail
  windows + slot [8] `NextAndGetResult` and the ForwardIterator
  `UpdateChildrenPinnedItersMgr` helper, both referenced by the tail
  implementations).
- `frames.txt` -- the FDE lines for the 80 excerpt windows.
- `relocations.txt` -- the 510 `.rela.dyn` entries backing the 21
  vtables (typeinfo slot + slots 0-23).
- `callers.tsv` -- the 132 iterator-consumer dispatch sites.
- `census.py` -- regenerates `vtables_all.txt`, `windows.txt`,
  `tail_table.tsv`, `relocations.txt`, `callers.tsv` from the binary.
- `export_excerpts.py` -- regenerates `excerpts/` from `windows.txt`
  + `frames.txt`.
- `gen_records.py` -- regenerates `records.json` + `vtables.tsv`.
- `verify.py` -- re-derives the census, checks every excerpt
  byte-for-byte against fresh objdump, spot-checks 3 seeded-random
  instructions, re-verifies every dispatch site, and runs the model
  tests. Run: `python3 research/work-items/RE-001-iterator-vtable-tail-115/verify.py`
- `MANIFEST.sha256` -- SHA-256 of every file in this directory.

## Model and tests

`tools/iterator_vtable_tail.py` models the tail dispatch: every class
carries an explicit VTABLE (slot -> method) and `call_slot` dispatches
through it exactly as the binary's indirect call does.
`tests/test_iterator_vtable_tail.py` (14 tests) exercises the
behaviour end-to-end through `call_slot`: user-key stripping,
PrepareValue caching and failure status capture, the upper-bound
mapping, manager-gated pinning, the GetProperty property name and
status codes, the readahead round-trip, and the sentinel-key flag.

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so
`make verify`, `make test` and `make catalogue-check` cannot run here.
The packet's own `verify.py` and the model tests above are the checks
that were run; they pass. A tooled environment should still run the
repo gates before merging.
