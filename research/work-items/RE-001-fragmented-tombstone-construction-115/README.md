# RE-001: node #115 FragmentedRangeTombstoneIterator construction paths

## Bounded question

Who constructs the 0xc8-byte `FragmentedRangeTombstoneIterator`, with
what arguments, what is the sixth argument (+0x78), and what sets the
second shared_ptr at +0x48/+0x50? The answer is one complete
behaviour: the three constructors (raw list, shared_ptr<List>,
shared_ptr<Cache>), the probe-gated `SplitBySnapshot` that builds
split iterators, and the two production callers of the shared_ptr<List>
constructor — plus the consumers that re-wrap the split results.

This packet resolves three open unknowns from #3900 (the arg6
identity, the +0x48/+0x50 setter, the second ctor-A consumer) and one
from #3674 (the second ctor-A consumer in FDE `0x5f33950`), and
corrects two labels from #3674 (see Corrections).

## Answer (pinned)

- **Ctor A** (`0x5f31380`, catalogue:
  `FragmentedRangeTombstoneIterator(FragmentedRangeTombstoneList*,
  const InternalKeyComparator&, unsigned long, const Slice*, unsigned
  long)`, 232/239): vtable `0x64ccae0+0x10`, the comparator's +0x8
  qword duplicated at +0x28/+0x30 and (comparator, comparator+0x8)
  at +0x38/+0x40, both shared_ptr holders null, +0x68 = list, +0x70
  = seq, +0x78 = arg6, +0x80 = slice, the bounds pairs +0x88/+0x98
  = list+0x8 and +0x90/+0xa0 = list+0x18, +0xa8 = &this+0xb8. Its
  two callers are the host flag path (`0x5f0aa15`, arg6 = 0) and
  `SplitBySnapshot` (`0x5f33a3b`, arg6 = prev_snapshot+1).
- **Ctor List** (`0x5f31470`, catalogue:
  `FragmentedRangeTombstoneIterator(const shared_ptr<FragmentedRangeTombstoneList>&,
  const InternalKeyComparator&, unsigned long, const Slice*, unsigned
  long)`, 292/302) — the constructor the earlier packets missed:
  the same vtable and comparator fields, but the caller's
  shared_ptr<List> is copied into +0x48/+0x50 with the use-count
  bump (`lock addl` iff the global byte at `0x64ed290` is 0, else
  plain `addl`); the Cache holder stays null; +0x68 = the
  shared_ptr's ptr; bounds from list+0x8/+0x18. **This is what sets
  the second shared_ptr at +0x48/+0x50.** Its two callers are
  `CompactionRangeDelAggregator::NewIterator` (`0x5f293b3`, seq = -1,
  slice = null, arg6 = 0) and
  `BlockBasedTable::NewRangeTombstoneIterator` (`0x60fcf4b`, seq =
  the ReadOptions snapshot or -1, slice = ReadOptions+0x58, arg6 =
  0).
- **Ctor Cache** (`0x5f315a0`, catalogue:
  `FragmentedRangeTombstoneIterator(const shared_ptr<FragmentedRangeTombstoneListCache>&,
  ...)`, 292/302): same shape, but the shared_ptr<Cache> is copied
  into +0x58/+0x60 with the bump; +0x68 = cache+0x28; the List
  holder stays null; bounds from cache+0x8/+0x20. Pinned by #3674
  (its ctor B); not re-shipped as an excerpt here. Its only caller
  is the host cache path (`0x5f0ab05`, arg6 = 0).
- **arg6 (+0x78)** is the lower snapshot bound: a tombstone is
  visible when its seqnum >= arg6 (and <= the read seq at +0x70),
  per #3900. It is 0 (no lower bound) in every production caller
  except `SplitBySnapshot`, where it is prev_snapshot+1 — so a split
  covers (prev_snapshot, snapshot].
- **Probe** (`0x5f31250`, no catalogue row): `pthread_once(list+0x48,
  __once_proxy)` builds the list's sorted seqnum index on first use
  (the initializer `0x5f2eb90` is reached only through the libstdc++
  TLS handoff `__once_callable`/`__once_call` at `0x64ed818`/
  `0x64ed820`; it reads the u64 seq array at list+0x18..+0x20 and
  inserts deduped 0x28-byte nodes, key at +0x20, into the tree at
  list+0x58, root *(list+0x60), count list+0x78); then
  `lower_bound(lower)` over that index returns True iff a key exists
  and it is >= snapshot — i.e. iff NO indexed seqnum lies in [lower,
  snapshot). `SplitBySnapshot` creates the split iterator iff the
  probe is true.
- **SplitBySnapshot** (`0x5f33950`, catalogue:
  `FragmentedRangeTombstoneIterator::SplitBySnapshot(const
  std::vector<unsigned long>&)`, 456/486): iterates the snapshots
  ascending; per snapshot, probe → if true, `operator new(0xc8)` +
  ctor A (list = this+0x68, comparator = this+0x38, seq = snapshot,
  slice = this+0x80, arg6 = lower) → `_Rb_tree::_M_emplace_hint_unique`
  (`0x5f33670`, 632/650) inserts (snapshot, unique_ptr<iterator>)
  into the return map (first wins: a duplicate key keeps the first
  iterator and the new one is destroyed via vtable slot 1). The
  return struct is 0x38 bytes: a std::map at +0x08, and a +0x00
  qword no producer or consumer touches (see Unknowns).
- **Truncated split** (`0x5f269e0`, catalogue:
  `TruncatedRangeDelIterator::SplitBySnapshot`, 1205/1269): calls
  the owned iterator's `SplitBySnapshot` (this = *(this+0x00)),
  then for each (snapshot, iterator) builds a fresh 0x48-byte
  `TruncatedRangeDelIterator` (ctor `0x5f25960`, by contract) and
  inserts it into the outer return map. Its only caller is
  `CompactionRangeDelAggregator::AddTombstones` (`0x5f28815`).
- **Compaction NewIterator** (`0x5f29140`, catalogue:
  `CompactionRangeDelAggregator::NewIterator`, 831/910): finalizes
  the aggregator's fragment map, builds a 0x118-byte
  `TruncatedRangeDelMergingIter` temp (vtable `0x64cc8e8`), builds
  a `make_shared<FragmentedRangeTombstoneList>` (0xf8 = 0x10 control
  block + 0xe8 List) via the List ctor `0x5f37410` (cache =
  buffer+0x10, list = &temp, comparator = *(aggregator+8), arg4 = 1,
  scratch = *(aggregator+0x88)), destroys the temp via vtable slot
  1, then ctor List with seq = -1, slice = null, arg6 = 0, and
  stores the iterator at *out. Three direct callers are pinned
  (`0x5e1561d`, `0x5e1cd48`, `0x5ed0c70`, all in unnamed stripped
  FDEs in the compaction area).
- **BlockBasedTable** (`0x60fcee0`, catalogue:
  `BlockBasedTable::NewRangeTombstoneIterator`, 127/138): null
  cached list (subobject+0x208 shared_ptr) → return null; else
  ctor List as above.
- **No copy/move constructor exists.** The vtable-install census
  (RIP-relative lea → `0x64ccae0`) finds only the three ctors and
  the two dtors' vtable resets, so the second shared_ptr can only
  be set by ctor `0x5f31470`.

## Corrections to prior packets

1. `0x5f37410` constructs a `FragmentedRangeTombstoneList` (0xe8
   bytes), not a "cache": the `make_shared<List>` control-block
   typeinfo in NewIterator (vtable `0x64cc9b8`, typeinfo
   `std::_Sp_counted_ptr_inplace<FragmentedRangeTombstoneList>`,
   name string at `0x970d80`) proves the 0xe8 object is a List.
   #3674's "cache ctor" / "cache" labels for `0x5f37410` and its
   0xe8 object are superseded; the Cache is the separate struct
   ctor B (`0x5f315a0`) takes a shared_ptr to.
2. The 0x80-byte source object consumed by `0x5f37410` in the host
   is a `MemTableIterator` temp (vtable `0x64cc638`, typeinfo
   `rocksdb::MemTableIterator`, embedded KeyComparator `0x64cc600`
   and InternalKeyComparator `0x64c8fe8`), not a
   `FragmentedRangeTombstoneList`. #3674's "list" label for it is
   superseded. In NewIterator the source is a
   `TruncatedRangeDelMergingIter` temp (0x118 bytes, vtable
   `0x64cc8e8`, typeinfo
   `rocksdb::(anonymous)::TruncatedRangeDelMergingIter`).
3. The List struct's index fields are now pinned: +0x48 is the
   pthread_once_t for the seqnum index, +0x58 is the index tree
   header (root at +0x60), +0x78 is the index count, and +0x18/+0x20
   is the u64 seq array the index is built from.

## Evidence

- `records.json` — semantic records only (no per-instruction
  mnemonic list; instruction-level detail lives in the raw
  excerpts). The census section is produced by `census.py`, so it
  always agrees with the census script.
- `callers.tsv` — every caller site of the census targets plus the
  NewIterator and List-ctor caller sets, with the containing FDE.
- `relocations.txt` — the RELATIVE/GLOB_DAT/TLS slots this packet
  relies on, with the typeinfo name strings resolved.
- `*.objdump.txt` — verbatim whole-function objdump excerpts,
  produced by `export_excerpts.py` with:
  `objdump -d --start-address=<start> --stop-address=<end> work/hl-node-115.bin`
  (GNU objdump 2.42). Mnemonics such as `endbr64` are genuine
  instructions present in the target binary, not placeholders.
- `frames.txt` — the FDE blocks for the eight windows, from
  `objdump --dwarf=frames`.
- `census.py` — the caller/tail/qword/RELATIVE/vtable-install scan
  (two independent scans — a slow per-byte scan and this fast regex
  scan — give identical output).
- `gen_records.py` — generates `records.json`, `callers.tsv` and
  `relocations.txt` from the binary.
- `verify.py` — the packet self-check (see below).
- `tools/fragmented_tombstone_construction_115.py` +
  `tests/test_fragmented_tombstone_construction_115.py` — the Python
  model of the three ctors, the probe, the split, the truncated
  split and the two ctor-List callers, with 481 tests (fixed cases
  plus seeded-random cross-checks of probe/split against linear
  references; random seed `0x5F33950`).

Run the self-check from the repository root:
`python3 research/work-items/RE-001-fragmented-tombstone-construction-115/verify.py`
— it re-runs objdump/readelf against the real binary and checks the
digest, the manifest, excerpt regeneration, fixed instruction
samples plus 3 seeded random gate spots byte-for-byte, the frames,
the census reproduction and every caller site, the relocations and
typeinfo names, the key immediates, and the model tests.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so the
repo's `make verify` / `make test` / `make catalogue-check` gates
cannot run here and are not claimed. The binary used is node #115,
SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). All claims are checked against that
binary by `verify.py`.

## Unknowns

- The source-level rationale for the probe gate: the interval
  semantics is pinned (create the split iff no indexed seqnum lies
  in [lower, snapshot)), but why a split is created exactly when
  its snapshot range contains no fragment start is open.
- The +0x00 qword of the SplitBySnapshot return struct: never
  written by either SplitBySnapshot nor read by
  `CompactionRangeDelAggregator::AddTombstones` (the caller's
  pre-call store to that slot holds a stale pointer no consumer
  reads).
- The List ctor `0x5f37410`'s arg4 (0 in the host, in FDE
  `0x5f0a3d0` and in FDE `0x6109c40`; 1 in NewIterator) and its r8
  scratch — by contract from #3674.
- The Cache struct's full layout beyond +0x08/+0x20/+0x28.
- The `TruncatedRangeDelIterator` ctor `0x5f25960`'s internals (by
  contract; its 7 call sites are the wrapper family).
- The Compaction NewIterator callers' source-level identities (the
  binary is stripped).
- The `TruncatedRangeDelMergingIter` temp's field names beyond the
  vtable.
- The landing-pad / LSDA tables of the windows.
