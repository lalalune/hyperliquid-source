# RE-001: pin node #115 the FilterPolicy builtin registrations 0x6137fe0

## Task and bounded question

Task **RE-001** (the node #115 function map). Which named FilterPolicy
factories does node #115 register at startup — the creators #4458 left
as an open unknown ("the creator routines themselves are not pinned")
— and what does each creator build? Also resolves #4458's second open
unknown in this area: "the registrar's base names before the
':false'/':true' suffixes".

## Answer

The builtin registrar `0x6137fe0` (FDE `0x6137fe0..0x61389e4`,
`RegisterBuiltinFilterPolicies`, sole caller `0x6138a48` in the
pthread_once init `0x6138a10`) registers **nine** FilterPolicy factories
under the single map key `"FilterPolicy"` (literal `0x44d20e`): one
inlined and eight through the per-factory registrar `0x6137810`
(FDE `0x6137810..0x6137d58`, exactly 8 E8 callers, all inside
`0x6137fe0`).

| # | Entry name | Pattern parts | Options | Invoker | Builds |
|---|------------|---------------|---------|---------|--------|
| 1 | rocksdb.BuiltinBloomFilter | (same) | — | 0x612de10 | ReadOnlyBuiltinFilterPolicy, 0x20 B, vtable 0x64d4af0 |
| 2 | bloomfilter | bloomfilter, rocksdb.BloomFilter | — | 0x6134130 | BloomFilterPolicy, 0x40 B, vtable 0x64d4f20 |
| 3 | bloomfilter | bloomfilter, rocksdb.BloomFilter | :false (tag 2) | 0x61338a0 | BloomFilterPolicy, 0x40 B, vtable 0x64d4f20 |
| 4 | ribbonfilter | ribbonfilter, rocksdb.RibbonFilter | :true (tag 2) | 0x6134010 | **BloomFilterPolicy**, 0x40 B, vtable 0x64d4f20 |
| 5 | ribbonfilter | ribbonfilter, rocksdb.RibbonFilter | — | 0x6133ef0 | RibbonFilterPolicy, 0x48 B, vtable 0x64d52e0 |
| 6 | ribbonfilter | ribbonfilter, rocksdb.RibbonFilter | : (tag 3) | 0x6133dc0 | RibbonFilterPolicy, 0x48 B, vtable 0x64d52e0 |
| 7 | rocksdb.internal.LegacyBloomFilter | (same) | — | 0x61339e0 | test::LegacyBloomFilterPolicy, 0x40 B, vtable 0x64d4fe0 |
| 8 | rocksdb.internal.FastLocalBloomFilter | (same) | — | 0x6133b30 | test::FastLocalBloomFilterPolicy, 0x40 B, vtable 0x64d50a0 |
| 9 | rocksdb.internal.Standard128RibbonFilter | (same) | — | 0x6133c80 | test::Standard128RibbonFilterPolicy, 0x40 B, vtable 0x64d5160 |

- **Per-factory registrar.** `0x6137810(library, spec, factory)` clones
  the factory record's functor through its manager with op 2 (a no-op
  for the stateless creator lambdas), deep-copies the 0x70-byte
  PatternEntry spec into a fresh heap entry (name string at `+0x08`,
  size at `+0x28`, names vector at `+0x30..+0x40`, flag byte at `+0x48`,
  accumulated length at `+0x50`, option-elements vector at
  `+0x58..+0x68`), builds a fresh 0x30-byte FactoryEntry record
  (vtable `0x64d53a0`, typeinfo
  `N7rocksdb13ObjectLibrary12FactoryEntryIKNS_12FilterPolicyEEE`: entry
  pointer at `+0x08`, functor at `+0x10..+0x20`, manager at `+0x20`,
  invoker at `+0x28`), locks the library mutex, calls the register
  helper `0x5fd1da0` at `0x6137b87` with `(library+0x28,
  "FilterPolicy")`, and appends the record to the returned map node's
  record list. The inlined first registration does the same steps
  inline (register call `0x613818f`).
- **PatternEntry** (0x70 bytes, vtable `0x64d8ed0`, typeinfo
  `N7rocksdb13ObjectLibrary12PatternEntryE`): 5 slots
  (`0x5ff2030`/`0x5ff2150`/`0x61f8670` (Matches)/`0x61f8120`/trailing
  zero). Built by the entry-builder helper `0x6134be0` (8 callers, all
  in `0x6137fe0`; cited, not pinned), which fills the name string from
  its C-string argument and adds a `:` option element (tag 4); the
  full name is appended to the names vector by `0x61350b0` (5 callers).
- **Creators.** Each invoker takes `(record, name, &slot, &string)`,
  stores the new raw object at the slot, releases the previous object
  through its vtable slot 1 when non-null, and returns the new object.
  Eight of the nine split the requested name on `:` (`0x61d2380`) and
  parse the second part as a double (`0x61d1e30`, preserved in `xmm0`
  across the allocation); the builtin creator `0x612de10` does no
  parsing at all — it allocates 0x20 zeroed bytes, stores vtable
  `0x64d4af0`, and returns. The Bloom creators go through ctor
  `0x6130160` (shared base ctor `0x612fc30`, then vtable `0x64d4f20`);
  the Ribbon creators go through helper `0x6131ec0` (0x48 bytes, ctor
  `0x6131e40`, which stores its int argument at `+0x40` and vtable
  `0x64d52e0`); the internal creators call the base ctor `0x612fc30`
  directly and store their own vtable. The `:` ribbon creator
  (`0x6133dc0`) parses a third `:`-part as an int (`0x61d1b90`) and
  passes it as the Ribbon int; the plain ribbon creator (`0x6133ef0`)
  passes 0.
- **The `:true` asymmetry.** The `:true`-suffixed ribbon factory
  (`0x6134010`) calls helper `0x6131df0` with `edi=1`, which allocates
  0x40 bytes and calls the Bloom ctor `0x6130160` — so it builds a
  **BloomFilterPolicy**, not a RibbonFilterPolicy. `0x6131df0`
  overwrites `edi` with `0x40` immediately, so the `1` is ignored.
  Whether upstream intends `:true` to select a Bloom policy is an open
  unknown; the bodies are pinned, the intent is not.
- **Managers.** The nine managers are one 0x2d-byte template at
  `0x612d2a0 + k*0x30`, byte-identical except the op-0 lea rel32: op 0
  stores the lambda typeinfo into `*rdi`, op 1 stores `rsi` into
  `*rdi`, op 2 (clone) and op 3 (destroy) return 0 (no-op). Their
  typeinfos (stepping `0x10` from `0x64d4a20`) all name the same
  `RegisterBuiltinFilterPolicies` lambda type. No manager has a direct
  E8 caller — they are reached only through the record's `+0x10`
  manager pointer — and no invoker has a direct E8 caller either.
- **Policy vtables.** All six have 23 slots (slot 22 a trailing
  zero). Slots 0/1 (Name/CreateFilter) and 14..21 differ per class;
  slots 2..13 are the shared FilterPolicy base slots; slot 19 is the
  shared tiny name function `0x612d290` (which returns
  `"rocksdb.BuiltinBloomFilter"` and has no E8 caller of its own) and
  slot 21 is the shared `0x61318a0`.
- **Name literals.** `rocksdb.BuiltinBloomFilter` is referenced from
  three lea sites (`0x612d294` in the tiny name fn `0x612d290`,
  `0x612fc24` inside the base ctor's TU, `0x6130144` in the name fn the
  registrar calls); `bloomfilter`/`rocksdb.BloomFilter` and
  `ribbonfilter`/`rocksdb.RibbonFilter` each come from their own tiny
  name fns; the internal names likewise; `:false` has a second lea
  site at `0x6130c06` outside this packet.

## Verification

`verify.py` reports ALL CHECKS PASSED (368/368: artifact digest,
manifest, excerpt regeneration, FDEs, raw-binary spot bytes, literals,
lea census, E8 census — including the nine invokers and the tiny name fn
having no direct E8 caller — vtable slots + typeinfo, manager template
identity, semantic-only records, model tests). `pytest` passes the model
tests (25 passed).

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify`, `make test` and `make catalogue-check` were not run in a tooled
environment; the packet's own `verify.py` (which re-checks the binary
bytes, the FDEs, the censuses and the model tests) was run instead and
passes. The evidence is bound to node #115 (`work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
— the full 64-char digest, stored from the start).

## Open unknowns

- The exact matching semantics of PatternEntry Matches (`0x61f8670`):
  how the entry name, pattern parts and option-element tags decide
  whether a requested name selects a factory.
- The exact parse semantics of the helpers `0x61d2380` (`:`-split),
  `0x61d1e30` (double parse) and `0x61d1b90` (int parse), including
  failure modes on malformed names.
- The field layout of the 0x40-byte BloomFilterPolicy / 0x48-byte
  RibbonFilterPolicy objects built by the shared base ctor `0x612fc30`
  (where the parsed double lands, what `+0x40` holds beyond the Ribbon
  int).
- Whether the `:true` ribbon factory building a BloomFilterPolicy is
  upstream intent or a registration quirk.
- The Name()/CreateFilter() bodies behind the per-class vtable slots
  0/1, and the tag meanings of the PatternEntry option elements
  (2, 3, 4) and the entry `+0x48` flag byte / `+0x50` accumulated
  length semantics.
- The remaining #4458 open unknowns not touched here: libraries vector
  element second qword; library `+0x08..+0x27` fields; map value
  owning type; control-block vtable slots 0..4; dispatcher `0x6137290`
  internals; wrapper `0x60dafb0`'s caller.
