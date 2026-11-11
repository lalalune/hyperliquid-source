# RE-001: node #115's per-CPU range-tombstone cache

## Bounded question

How does node #115 hand a calling thread a range-tombstone iterator
over a MemTable, and what owns the fragmented list's lifetime? The
answer is one complete behaviour: a per-CPU shared_ptr slot that is
claimed, checked for a ready flag, and lazily filled with a freshly
built fragmented list and its cache — plus the two iterator ctors
that consume either a raw list or the cached shared_ptr, and the
shard-pointer sibling that picks a 0x40-stride slot the same way.

This packet pins the internals of the sharded access that the merged
RE-014 packets (`RE-014-probe-gated-lookup-115`,
`RE-014-batch-lookup-115`) only reference by contract: their windows
call/tail-jump to `0x5f0a9c0` without modelling it. It also pins the
internals of the shard refresh `0x605e170`, which the merged
RE-001 allocate packets model by contract only
(`tools/shard_allocate_115.py` `refresh_shard`). The picker
`0x60d5cd0` and the seed `0x61c4080` are re-derived fresh from the
binary here (same routines as open PR #3613).

## Answer (pinned)

- **Host** (`0x5f0a9c0`, catalogue:
  `rocksdb::MemTable::NewRangeTombstoneIteratorInternal`, 1536/1676
  raw bytes): takes (owner, arg2, arg3, flag). When the flag is set
  it allocates a 0xc8-byte iterator and builds it via ctor A from
  the raw list at owner+0xce0, never touching the slot. Otherwise it
  picks the shard — CPUID picker `0x60d5cd0`, or the per-thread seed
  advanced once when the picker returns -1 — masks with
  `(1 << shift) - 1` (shift = owner+0xd18), and takes the 16-byte
  shared_ptr slot at owner+0xd10 + idx*0x10. A `_Sp_locker` claims
  the slot, the 16-byte shared_ptr is copied, and a non-null control
  block's use count is bumped (`lock addl` iff the global byte at
  `0x64ed290` is 0, else plain `addl`). When the slot object's ready
  flag byte (+0x30) is set, the iterator is built via ctor B from
  the stack copy and the claim-time reference is released. When it
  is clear, the slot object's mutex (+0x0) is locked: a non-null
  cache at +0x28 takes the same ctor-B path, a null cache triggers
  the lazy build.
- **Lazy build**: a 0x80-byte list is built (vtable `0x64cc638+0x10`,
  Cleanable at +0x8, the owner fields at +0x30/+0x48/+0x50/+0x5a/
  +0x60/+0x78 — see `records.json`), a 0xe8-byte cache is built
  from it by `0x5f37410`, the cache is installed at slot-object
  +0x28 (tearing down any old cache — defensive here, see below),
  the temporary list is destroyed via its vtable slot 1, the ready
  flag is set to 1, the mutex is unlocked, and the iterator is built
  via ctor B. The old-cache teardown runs the +0xc0 array fixup
  (memmove/memcpy + insertion-sort dedup, entry dtors, the +0x98
  cleanup chain), frees the array, runs `DoCleanup(+0x98)`, walks
  the +0x80 list (0x30-byte nodes) and the +0x60 list (0x28-byte
  nodes via `0x5f059b0`), frees the +0x30/+0x18/+0x0 buffers and
  deletes the 0xe8 cache. The teardown branch is defensive in this
  flow: the mutex is held from the null check through the install,
  so the old value is null in the single-threaded flow.
- **Ctor A** (`0x5f31380`, catalogue:
  `FragmentedRangeTombstoneIterator(list, comparator, seq, slice,
  arg6)`, 232/239): vtable `0x64ccae0+0x10`, the comparator's +0x8
  qword duplicated at +0x28/+0x30 and (comparator, comparator+0x8)
  at +0x38/+0x40, +0x68 = list, +0x70 = seq, +0x78 = arg6, +0x80 =
  slice, the bounds pairs +0x88/+0x98 = list+0x8 and +0x90/+0xa0 =
  list+0x18, +0xa8 = &this+0xb8; the shared_ptr at +0x58 is null.
- **Ctor B** (`0x5f315a0`, catalogue:
  `FragmentedRangeTombstoneIterator(shared_ptr<Cache>, comparator,
  seq, slice, arg6)`, 292/302): same vtable and comparator fields;
  the 16-byte shared_ptr is copied to +0x58 and its control block
  bumped (same global-flag rule); +0x68 = the shared_ptr object's
  +0x28 (the cache); an empty slice is treated as null; the bounds
  pairs are +0x88/+0x98 = cache+0x8 and +0x90/+0xa0 = cache+0x20.
  The two ctors read different bound offsets because the cache is a
  different struct from the raw list; the iterator distinguishes
  them by the null/non-null shared_ptr at +0x58.
- **Cache ctor** (`0x5f37410`, by shape): zero-inits the 0xe8 cache
  (+0x68/+0x70 = &cache+0x58, +0x80..0x90 a self-referential pair,
  Cleanable at +0x98, index vector triple +0xc0/+0xc8/+0xd0, count
  +0xd8, total +0xe0), then walks the list via vtable slots 0x10
  (Valid), 0x18 (Next), 0x50 (key), 0x60 (size), 0x38 and 0x90,
  counting entries at +0xd8 and summing sizes at +0xe0 behind a
  perf-level gate, builds the sorted index vector, and finalizes
  through `0x5f36c70` (both the main and the null-list paths).
- **Shard helper** (`0x605e170`, by shape): same picker/seed mask,
  but table owner+0x48, shift owner+0x50 and a 0x40 stride; it
  records `idx | (1 << shift)` in TLS at fs:0-0x408 and returns the
  slot pointer. Its callers are the merged allocate windows
  `0x5f117a0` and `0x5f11c40`.
- **Picker** (`0x60d5cd0`, catalogue `rocksdb::port::PhysicalCoreID`,
  32/32): cpuid leaf 0 gives the max leaf; 0 returns -1, otherwise
  leaf 1 EBX>>24. Six direct call sites. **Seed** (`0x61c4080`):
  `_Hash_bytes(&pthread_self, 8, 0xc70f6907) & 0x7fffffff` (or 1),
  cached per thread; callers advance it by `*0x41a7 mod 0x7fffffff`
  (Mersenne fold). Seventeen direct call sites.
- **Cleanable** (`0x61bd0c0` ctor, `0x61bd0e0` `DoCleanup`, catalogue
  78/81): the ctor zeroes the head (+0x0) and the chain link
  (+0x18); the dtor runs the head's fn, then walks the +0x18 chain
  running each node's fn and freeing the 0x20-byte nodes.
- **Release** (`0x5d350c0`, catalogue
  `_Sp_counted_base::_M_release`, 126/133): the +0x8 qword holds
  (use, weak); 0x100000001 disposes at once (vtable slot 0x10,
  then destroy via slot 0x18); otherwise the use count is
  decremented (`lock xadd` iff the global byte is 0) and disposal
  follows iff the old count was 1.
- **List release** (`0x5f059b0`, by shape): recursively releases a
  tree of 0x28-byte nodes (+0x18 child first, then the node, then
  the +0x10 sibling).

## Evidence

- `records.json`: semantic records only (no per-instruction mnemonic
  list). Instruction-level detail lives in the raw disassembly
  excerpts below, kept verbatim and whole-function. Mnemonics such
  as `endbr64` are genuine instructions present in the target binary,
  not placeholders.
- Whole-function verbatim excerpts (`*.objdump.txt`, regenerated by
  `export_excerpts.py`): host, shard helper, picker, seed, ctor A,
  ctor B, cache ctor, Cleanable ctor/dtor, release, list release.
- `frames.txt`: the 11 FDE blocks from `objdump --dwarf=frames`.
- `callers.tsv`: every census site with its containing FDE and role
  (62 sites, each confirmed as a real call/jump in its FDE). The
  three generic helpers (Cleanable ctor/dtor, `_M_release`) are
  libstdc++/RocksDB-wide with 103 / 223+32 / 1273+25 call sites;
  their full caller lists add no RE value, so the packet pins only
  the sites this behaviour uses (`packet_internal_sites` in
  `records.json`: 5 + 1 + 1 sites, each verified in its FDE).
- `relocations.txt`: no `R_X86_64_RELATIVE` entry points at a packet
  window; the vtables and the atomicity-selector global are
  RIP-relative.
- `verify.py`: the packet checker — run it from the repo root. It
  re-derives the excerpts, byte-checks fixed samples plus 3 seeded
  random gate spots against a fresh objdump run and the raw binary,
  re-runs the census, verifies every census site and every
  in-packet generic-helper site in its FDE, re-checks the model
  constants, and runs the model tests.
- `census.py` / `gen_records.py`: regenerate the census and
  `records.json` from the binary.

## Model and tests

- `tools/range_tombstone_cache_115.py`: the Python model (picker,
  seed + Mersenne step, counted base, Cleanable, node-tree release,
  the 0x80 list and 0xe8 cache builds, the two iterator ctors, the
  host state machine, the 0x40-stride shard helper).
- `tests/test_range_tombstone_cache_115.py`: 112 checks, all passing.

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
relocation-qualified matches (1536/1676, 232/239, 292/302, 32/32,
78/81, 126/133), not this packet's own rebuilds. The shard helper,
cache ctor, seed, Cleanable ctor and list release are identified by
shape, not by a catalogue row.

## Open unknowns

See `records.json` `unknowns`: the host's live rdx argument vs the
catalogue name; the list's +0x30/+0x38/+0x40 vtable-valued slots;
the owner fields beyond the shard table; which store populates
cache+0x8/+0x20; the cache index entry layout and the 0x5f36c70
finalize contract; the 0x5f32900 contract; the shard helper's TLS
record consumer; the 0x64ed290 global's identity; the cache ctor's
r8 scratch type; the shared landing-pad stubs; the defensive
old-cache teardown; the sibling cache builder in FDE 0x5f0a3d0; the
memmove/memcpy helpers' contracts.
