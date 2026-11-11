# RE-001: node #115's fragmented-range-tombstone construction

## Bounded question

How does node #115 (re)build a MemTable's fragmented range-tombstone
cache, and what happens to the cache that was already there? The
answer is one complete behaviour: the `ConstructFragmentedRangeTombstones`
host — its already-built early return, the temporary `MemTableIterator`
built field-wise from the owner, the `ReadOptions` stack temp, the
fresh cache built from the iterator, the install at `owner+0xce0`,
and the old-cache teardown, whose sorted index is re-sorted,
deduplicated and invoked entry by entry before the cache is freed.

This packet resolves open PR #3674's open unknown "the sibling cache
builder in FDE 0x5f0a3d0" and corrects its labels for the two sort
helpers: they are not `memmove`/`memcpy` but libstdc++ `std::sort`
internals (`__introsort_loop`, `__insertion_sort`, `__adjust_heap`),
identified from the depth limit, the 16-entry threshold and the
heapsort fallback.

## Answer (pinned)

- **Host** (`0x5f0a3d0`, catalogue:
  `rocksdb::MemTable::ConstructFragmentedRangeTombstones`, 1238/1337
  raw bytes): takes only the owner (MemTable). When the flag byte at
  owner+0xa60 is set it returns at once. Otherwise it builds a
  temporary 0x80-byte iterator, builds a 0xe8-byte cache from it,
  installs the cache at owner+0xce0 and tears down the old cache
  found there. Callers: `DBImplSecondary::RecoverLogFiles`,
  `DBImpl::SwitchMemtable`, `FlushJob::MemPurge` (see `callers.tsv`).
- **Temp iterator**: operator new(0x80); Cleanable ctor `0x61bd0c0`
  at +0x8; vtable `0x64cc638+0x10` (`rocksdb::MemTableIterator`, 24
  slots, typeinfo `N7rocksdb16MemTableIteratorE`); the owner fields
  at +0x30 (owner+0xc58), +0x48 (owner+0x10, the user comparator),
  +0x5a (owner+0x31 ^ 1), +0x60 (owner+0x6c), +0x78 (owner+0x60);
  an embedded `MemTable::KeyComparator` at +0x38 (vtable
  `0x64cc600+0x10`, 5 slots) whose `InternalKeyComparator` member
  sits at +0x40 (vtable `0x64c8fe8+0x10`, 3 slots) with its
  user_comparator_ at +0x48; +0x50 is the result of the
  (owner+0xa58)->vtable slot 0x90 call with (obj, 0, 0) — the rep
  iterator. The build is field-wise in the host (the
  `MemTableIterator` ctor is inlined). After the cache ctor returns,
  the iterator is destroyed via its vtable slot 1 (`0x5f058e0`).
- **ReadOptions temp** (`0x60b21f0`, catalogue
  `rocksdb::ReadOptions::ReadOptions`, 114/114): default-constructed
  on the stack at rsp+0x30; the init map is pinned byte-exact in
  `records.json` (+0x2c = 0x101, +0x78 = -1, +0x84 = 4, +0x88 =
  0x0100, everything else 0 over the 0x8a-byte span). The host then
  reads temp+0x48 as a function pointer and would invoke it as
  fn(temp+0x38, temp+0x38, 3) when non-null — but the ctor zeroes
  +0x48 and no store in this flow rewrites it, so the call never
  fires here. 61 direct call sites binary-wide; the host's is
  `0x5f0a43d`.
- **Cache build**: operator new(0xe8); cache ctor `0x5f37410`(cache,
  &iterator, iterator+0x8, 0, scratch) where scratch is a 0x20-byte
  zeroed stack `vector<size_t>` at rsp+0x10 (begin/end/capacity);
  after the ctor the scratch heap array is freed with operator
  delete[](begin, capacity - begin). The cache ctor and its
  `FragmentTombstones` finalize (`0x5f36c70`, catalogue
  `FragmentedRangeTombstoneList::FragmentTombstones`) are by
  contract here; their excerpts are re-shipped from #3674.
- **Sort machinery** (all by shape, no catalogue row): the old
  index vector (16-byte entries, vector triple at cache+0xc0/+0xc8/
  +0xd0) is sorted lexicographically by (first, second) with
  `std::sort` — `__introsort_loop` `0x5f053d0` (no-op at or below 16
  entries, median-of-three pivot, `__unguarded_partition`, recurse
  right / loop left, heapsort fallback at depth 0 via
  `__adjust_heap` `0x5f04f80`), then `__insertion_sort` `0x5f05120`
  plus the host's inlined unguarded insertion loop
  (`__final_insertion_sort`). The depth limit is
  2*floor(log2(n)), or -2 when n == 0. Adjacent duplicates are then
  compacted in place (inlined at 0x5f0a823) and the vector end
  (+0xc8) is updated.
- **Old-cache teardown**: when the old cache's +0xb8 ready flag is
  set, the sorted/deduped index entries are invoked one by one as
  entry[1](entry[0]); then the +0x98 head cleanup fn runs as
  fn(+0xa0, +0xa8), each 0x20-byte node of the +0xb0 chain runs as
  fn(+0x8, +0x10) and is freed (0x20 bytes), and +0x98/+0xb0 are
  zeroed. When the flag is clear, the +0xc0 array is freed without
  invoking its entries. The common tail then frees the +0xc0 array
  (operator delete[], size +0xd0 - +0xc0), runs DoCleanup(+0x98)
  (a no-op after the ready path zeroed it), walks the +0x80 list
  (0x30-byte nodes), releases the +0x60 tree via `0x5f059b0`,
  frees the +0x30/+0x18/+0x0 buffers, and deletes the 0xe8 cache.
  Unlike #3674's host, where this teardown is defensive (the mutex
  is held, so old is null), this host holds no lock: a non-null old
  cache is a live path here, so the sort/dedup/invoke sequence
  runs on real entries.
- **Cleanable** (`0x61bd0c0` ctor, `0x61bd0e0` `DoCleanup`,
  re-shipped from #3674): the ctor zeroes the head (+0x0) and the
  chain link (+0x18); DoCleanup runs the head's fn, then walks the
  +0x18 chain running each node's fn and freeing the 0x20-byte
  nodes.
- **List release** (`0x5f059b0`, by shape, re-shipped from #3674):
  recursively releases a tree of 0x28-byte nodes (+0x18 child
  first, then the node, then the +0x10 sibling).
- **Landing pads**: the five endbr64 stubs at 0x5f0a8cd..0x5f0a8fd
  each save %rax to %rbx and jump to 0x5f0a31a/0x5f0a33a/0x5f0a353/
  0x5f0a382/0x5f0a3a4 in the preceding FDE (a shared rethrow block);
  not decoded.

## Evidence

- `records.json`: semantic records only (no per-instruction mnemonic
  list). Instruction-level detail lives in the raw disassembly
  excerpts below, kept verbatim and whole-function. Mnemonics such
  as `endbr64` are genuine instructions present in the target binary,
  not placeholders.
- Whole-function verbatim excerpts (`*.objdump.txt`, regenerated by
  `export_excerpts.py`): host, ReadOptions ctor, `__introsort_loop`,
  `__insertion_sort`, `__adjust_heap`, cache ctor, Cleanable
  ctor/dtor, list release. The cache-ctor, Cleanable ctor/dtor and
  list-release excerpts are re-shipped byte-identically from open PR
  #3674 (same binary, so regeneration reproduces them); the host,
  ReadOptions ctor and the three sort helpers are new in this PR.
- `frames.txt`: the 9 FDE blocks from `objdump --dwarf=frames`.
- `callers.tsv`: every census site with its containing FDE and role
  (94 sites, each confirmed as a real call/jump in its FDE). The
  two generic helpers (Cleanable ctor/dtor) are libstdc++/RocksDB-wide
  with 103 / 223+32 call sites; their full caller lists add no RE
  value, so the packet pins only the sites this behaviour uses
  (`packet_internal_sites` in `records.json`: 1 + 1 sites, each
  verified in its FDE).
- `vtables.tsv`: the three iterator vtables resolved through
  R_X86_64_RELATIVE entries — typeinfo names and every slot target
  (MemTableIterator 24 slots, KeyComparator 5, InternalKeyComparator 3).
- `relocations.txt`: no `R_X86_64_RELATIVE` entry points at a packet
  window; the vtable resolutions are recorded in `vtables.tsv`.
- `verify.py`: the packet checker — run it from the repo root. It
  re-derives the excerpts, byte-checks fixed samples plus 3 seeded
  random gate spots against a fresh objdump run and the raw binary,
  re-runs the census, verifies every census site and every
  in-packet generic-helper site in its FDE, re-checks the vtable
  resolutions, and runs the model tests.
- `census.py` / `gen_records.py`: regenerate the census and
  `records.json` from the binary.

## Model and tests

- `tools/fragmented_range_tombstones_115.py`: the Python model
  (ReadOptions init map, the temp-iterator field map, faithful
  `__insertion_sort` / `__adjust_heap` / `__make_heap` /
  `__sort_heap` / `__introsort_loop` / `__final_insertion_sort`,
  the dedup compaction, Cleanable, the node-tree release, the
  0xe8 cache teardown, the host state machine).
- `tests/test_fragmented_range_tombstones_115.py`: 299 checks, all
  passing, including the faithful sort machinery validated against
  Python's `sorted()` on seeded random inputs (sizes 0..200,
  duplicates, reverse-sorted, all-equal, depth-0 heapsort fallback).

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
relocation-qualified matches (1238/1337, 114/114), not this packet's
own rebuilds. The sort helpers, the cache ctor, the seed, the
Cleanable ctor and the list release are identified by shape, not by
a catalogue row.

## Open unknowns

See `records.json` `unknowns`: the owner+0xa60 flag's setter; the
owner fields beyond the shard table; the ReadOptions per-field source
names and the +0x48 slot's identity; the +0xc0 index entries'
semantic identity; the `FragmentTombstones` finalize internals; the
cache ctor's stack-iterator vtable slots; the landing-pad stubs; the
0x5f32900 contract; the sibling teardown FDEs' entry conditions.
