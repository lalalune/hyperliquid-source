# RE-001: pin node #115 fragmented range-tombstone cache destruction

**Task:** RE-001. **Bounded question:** how is the node #115 fragmented
range-tombstone cache destroyed — the `shared_ptr` dispose, the
`unique_ptr` destructor, and `MemTable::~MemTable`?

This work item resolves the open unknown left by PR #3803
(RE-001-fragmented-range-tombstones-115): "the sibling teardown FDEs'
entry conditions". It pins one complete behavior: the three ownership
shapes of the same 0xe8-byte teardown (the `shared_ptr` control-block
dispose at 0x5f061b0, the `unique_ptr<List>` destructor at 0x5f0b080,
and the inlined teardown inside `MemTable::~MemTable` at 0x5f10d40),
the `MemTable` destructor's full member-destruction order, the
`AllocTracker` / `WriteBufferManager` pair it ends with, and the
`shared_ptr` release chain that reaches the dispose.

## Evidence

- Artifact: `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (see `provenance/artifacts.json`).
- `records.json` holds semantic records only: window identities, the
  behavior records (dispose state machine, `MemTable` destructor order,
  `AllocTracker` state machine, release chain, RB-erase, `FlushJobInfo`
  destruction, construction-side evidence), vtable resolutions, the
  caller census, and the open unknowns. It does **not** contain a
  per-instruction mnemonic list; instruction-level detail lives only in
  the verbatim objdump excerpts.
- The `*.objdump.txt` files are the raw, unmodified output of
  `objdump -d --start-address=<start> --stop-address=<stop>
  work/hl-node-115.bin`, one file per whole function, produced by
  `export_excerpts.py` (committed here). Mnemonics such as `endbr64`
  are genuine instructions present in the target binary, not
  placeholders.
- `census.py` reproduces the caller census from the binary
  (E8/E9 scan over `.text`, whole-file qword search, `.rela.dyn`
  `R_X86_64_RELATIVE` parse). `verify.py` re-runs it and checks every
  census site is a real call/jump in its containing FDE.
- `frames.txt` lists the `.eh_frame` FDE line for each window.
  `callers.tsv` lists every direct caller and tail-jump site.
  `relocations.txt` lists the `.rela.dyn` entries that bind the packet
  windows into vtables. `vtables.tsv` lists the resolved vtable slots.

## What the binary shows

- The cache teardown (0x5f061b0) loads the `FragmentedRangeTombstoneList*`
  from the control block at +0x38; a null list returns without freeing.
  If the cache +0xb8 flag is set it takes the sort/dedup/invoke path
  (sort the index with `__introsort_loop` + `__insertion_sort`, invoke
  each entry destructor, update the end at +0xc8, walk the +0xb0 chain);
  otherwise it frees the index array directly. Both paths rejoin a
  common tail: free the +0xc0 array, `Cleanable::DoCleanup(+0x98)`,
  walk the +0x80 list, release the +0x60 tree via 0x5f059b0, free the
  +0x30/+0x18/+0x00 buffers, `operator delete` the 0xe8-byte block.
- The `unique_ptr<List>` destructor (0x5f0b080) is the same teardown
  with the cache at owner +0x00. Its only standalone caller is the
  `MemTable` constructor's exception cleanup; the normal
  `MemTable::~MemTable` path inlines it at +0xce0.
- `MemTable::~MemTable` destroys, in order: `AllocTracker::FreeMem`
  (+0x80), the +0xd10 `CoreLocalArray` elements (one `_M_release` each),
  the +0xce0 cache, the +0xcd8 `unique_ptr<FlushJobInfo>`, the +0xc90
  chain, the +0xc80 inline array, +0xc60, the +0xc40 rwlock vector, the
  +0xbf8/+0xbd0 strings, the +0xba8/+0xb90 buffers, the +0xb78/+0xb60
  vectors, the +0xb40 RB-tree, the +0xb18 vector, the +0xac0/+0xaa0
  strings, the two reps (+0xa58/+0xa50) via vtable slot 0x88, then the
  `ConcurrentArena` at +0xa0 (`Arena::~Arena(+0x100)`, `operator
  delete[]` on *(+0xe8)), and tail-jumps to
  `AllocTracker::~AllocTracker` (+0x80).
- `AllocTracker::FreeMem` calls `DoneAllocating()` first when +0x10 is
  clear, returns early when already freed (+0x11), and otherwise hands
  the manager the `tracker+0x8` amount through
  `WriteBufferManager::FreeMem`. `DoneAllocating` subtracts the same
  amount from the manager's second counter (+0x18) via 0x606a110.
- The release chain: a `CoreLocalArray` element's inner control block
  dispose (0x5f0a290) decrements the Cache control block's use count
  and, at count 1, calls its vtable slot 0x10 (the Cache `_M_dispose`,
  0x5f061b0) and tail-jumps to slot 0x18 (`_M_destroy`).
- `MemTable::~MemTable` has 15 direct callers, among them
  `JobContext::Clean`, `SuperVersion::~SuperVersion`,
  `ColumnFamilyData::~ColumnFamilyData`, `DBImpl::SwitchMemtable`,
  and `ForwardIterator::SVCleanup`. The `MemTable` constructor has two
  callers: `ColumnFamilyData::ConstructNewMemtable` and
  `FlushJob::MemPurge`.

## Re-shipped excerpts

Five excerpts are byte-identical re-ships from PR #3803
(`RE-001-fragmented-range-tombstones-115`): `__introsort_loop`
(0x5f053d0), `__insertion_sort` (0x5f05120), `__adjust_heap`
(0x5f04f80), `Cleanable::DoCleanup` (0x61bd0e0), and the list release
(0x5f059b0). They are shared helpers of the dispose, the `unique_ptr`
destructor and the `MemTable` destructor, so this packet re-ships them
to stay self-contained; `verify.py` checks the byte-identity against
the original packet.

## Model

`tools/tombstone_cache_destruction_115.py` models the cache/list
teardown state machine (flag gates, sort/dedup/invoke, `Cleanable`
head + chain, the 0x80-list walk, the 0x60-tree release, buffer frees,
the 0xe8 delete), the three entry shapes, the `MemTable` destructor
member order, the `AllocTracker` / `WriteBufferManager` state machine,
the `shared_ptr` release chain, RB-erase for 0x30/0x60-byte nodes, and
`FlushJobInfo` destruction. `tests/test_tombstone_cache_destruction_115.py`
exercises it end-to-end (about 200 checks).

## Open unknowns (recorded, not presented as facts)

- The +0xa98 `VersionEdit` asymmetry: the constructor's `.cold` path
  calls `VersionEdit::~VersionEdit(+0xa98)` but the normal destructor
  destroys only the strings at +0xaa0/+0xac0, and the constructor body
  never constructs a `VersionEdit` there.
- The precise C++ element type of the +0xd10 `CoreLocalArray`.
- The identity of the slot-0x88 calls on the reps; slot 17 of the
  `SkipListRep` vtable resolves to the 0x58-byte delete stub 0x6063010.
- The `WriteBufferManager` +0x0/+0x20 gate identities.
- The individual `FlushJobInfo` string/map field names.
- The `MemTable` vtable (no `N7rocksdb8MemTableE` typeinfo name string
  found by a plain string search; `MemTable` is deleted directly by 15
  callers, not virtually).

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java. The
reconstruction was verified against the node #115 binary only, with
`objdump`/`readelf` and the Python model; the repo's `make verify` /
`make test` / catalogue-check gates need a tooled machine and were not
run here.
