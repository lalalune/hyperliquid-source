# RE-001: pin node #115 RegisterTtlObjects

## Task and bounded question

Task **RE-001** (the node #115 function map). What does
`rocksdb::RegisterTtlObjects()` register, how is it reached exactly
once, and what does each creator lambda build when it is invoked?

## Answer

The creator `0x6208290..0x6208afa` (catalogue identity
`_ZN7rocksdb18RegisterTtlObjectsEv`, 1,882/2,154 published-crate
rebuild match) registers three `FactoryEntry` records in the `TTL`
`ObjectLibrary`:

| # | map name | creator (`_M_invoke` / manager) | pattern | elements | flag | registration |
|---|----------|----------------------------------|---------|----------|------|--------------|
| 1 | `MergeOperator` | MO `0x62056b0` / `0x62009a0` | `TtlMergeOperator` | — | 1 | inline find-or-insert + append |
| 2 | `CompactionFilterFactory` | CFF `0x6205c60` / `0x62009d0` | `TtlCompactionFilterFactory` | — | 1 | register helper `0x5ff8260` |
| 3 | `CompactionFilter` | CF `0x6202ca0` / `0x6200a00` | `TtlCompactionFilter` | — | 1 | inline find-or-insert + append |

- The register function `0x62069f0..0x6206d29` calls the registry
  getter `0x61f92b0` (PR #4015), builds the 0x90-byte `make_shared`
  library block (control-block vtable `0x64d00f0`, counts
  `0x100000001`, SSO name `TTL`) and appends it to the registry
  libraries vector under the registry mutex (registry+0x98; the
  full path goes through vec-insert `0x5ff7960`, PR #4015). It then
  invokes the creator through a `std::function` (functor
  `0x6208290`, manager `0x6201000`, invoker `0x6200a30`) with the
  library and an empty-string name, destroys the function (manager
  op 3) and releases the registry copy.
- The once-wrapper `0x6202da0..0x6202e78` runs the register function
  exactly once (`pthread_once` on the control at `0x65093a8`,
  callable via the TLS `__once_callable` slots; failure throws
  `__throw_system_error`). It has exactly two direct callers, both
  verified as real `call 6202da0` instructions: `DBWithTTL::Open`
  at `0x620615d` and `DBWithTTLImpl::CreateColumnFamilyWithTtl` at
  `0x6205d61` (which calls it first, before `SanitizeOptions`).
- The creator locks the library mutex around each registration
  block, then calls count `0x61f8700` (PR #3983); both the returned
  total-entry count and the element-count out value are discarded.
  Its cold FDE holds only exception landing pads.
- All three `PatternEntry` records have empty sub-pattern and
  element vectors and flag 1, so all three match exactly.

## Creators

- **MO** `0x62056b0` builds a `TtlMergeOperator` via C1 `0x6205560`
  (243/267, 91.01%) with an empty `shared_ptr<MergeOperator>` and a
  null `SystemClock`, registers `TtlMergeOptions` (global
  `0x6509480`), installs into the out unique_ptr (replacing and
  D1-destroying any previous object) and returns the new pointer.
- **CFF** `0x6205c60` builds a `TtlCompactionFilterFactory` via C2
  `0x6205790` with ttl 0, a null clock and an empty
  `shared_ptr<CompactionFilterFactory>`, registers `UserOptions`
  (global `0x6509400`) and `TTL` (global `0x6509440`), installs
  into the out unique_ptr and returns the new pointer.
- **CF** `0x6202ca0` builds a `TtlCompactionFilter` via C2
  `0x6202a10` with ttl 0, a null clock, a null filter and an empty
  unique_ptr, registers `TTL` (global `0x6509440`) and `UserFilter`
  (global `0x65093c0`), and returns the raw pointer directly --
  unlike the other two invokers it installs into no out slot.

## Consumers

- `DBWithTTLImpl::SanitizeOptions` (`0x6205a00..0x6205c18`,
  455/536) calls the `TtlMergeOperator` C1 at `0x6205aa0`, the
  `TtlCompactionFilter` C2 at `0x6205a5d` and the
  `TtlCompactionFilterFactory` C2 at `0x6205b6c`.
- `TtlCompactionFilterFactory::CreateCompactionFilter`
  (`0x6202ba0..0x6202c60`, 170/192) calls the
  `TtlCompactionFilter` C2 at `0x6202c01`.

Both are cited by call site, FDE and catalogue row, not
re-excerpted: their bodies are mostly other logic.

## Layouts

- `ObjectLibrary` (0x80-byte object inside the 0x90-byte
  `make_shared` block; control block is the first 0x10 bytes:
  vtable `0x64d00f0`, counts `0x100000001`): +0x00 mutex (0x28
  bytes, zero-initialized), +0x28 unordered_map (0x38 bytes:
  buckets = single-bucket self-pointer, bucket_count 1,
  before_begin 0, element_count 0, max_load_factor 1.0f,
  next_resize 0, single_bucket 0), +0x60 name string (`TTL`).
- `PatternEntry` (0x70 bytes, vtable `0x64d8ed0`, pinned by PR
  #3983): +0x08 pattern string, +0x28 pattern-length copy, +0x30
  vector of plain strings, +0x48 flag byte, +0x50 pointer, +0x58
  vector of 0x28-byte `{string, mode u32}` elements.
- `FactoryEntry` (0x30 bytes): +0x00 vtable, +0x08
  `PatternEntry*`, +0x10..+0x20 `std::function` functor storage
  (16 zero bytes for these stateless lambdas), +0x20 manager,
  +0x28 invoker. D2 installs the base vtable, calls
  `manager(this+0x10, this+0x10, op 3)` when the manager is
  non-null, then deletes the `PatternEntry` through its vtable
  slot 1; D0 adds `operator delete(node, 0x30)`.
- `std::function` managers `0x62009a0` / `0x62009d0` / `0x6200a00`
  (and the register manager `0x6201000`): op 0 stores the
  typeinfo address, op 1 clones the functor, op 2 and op 3 are
  no-ops here (the effective clone is the bitwise
  `punpcklqdq`/`movdqa` copy of the `{manager, invoker}` pair,
  manager at the lower address, invoker at the higher).
- `TtlMergeOperator` (0x38 bytes, vtable `0x64d9558`): +0x08
  vector<string>, +0x20 `shared_ptr<MergeOperator>`, +0x30
  `SystemClock*`.
- `TtlCompactionFilterFactory` (0x40 bytes, vtable `0x64d9718`):
  +0x08 vector<string>, +0x20 ttl (int), +0x28 `SystemClock*`,
  +0x30 `shared_ptr<CompactionFilterFactory>`.
- `TtlCompactionFilter` (0x40 bytes, vtable `0x64d9630`): +0x08
  vector<string>, +0x20 `const CompactionFilter*`, +0x28 owned
  `unique_ptr` pointer, +0x30 ttl (int), +0x38 `SystemClock*`.
  The +0x08 field is proven to be a `vector<string>` for this
  object by its ctor's unwind path (element stride 0x30); the
  other two are recorded by identical shape.
- Matching follows the pinned str-match `0x61f8430` + elem-match
  `0x61f8280` semantics (PR #3983): empty element vector means
  exact match only. So each entry matches only its own pattern.

## Correction to PR #4028

The 1.0f word at block+0x58 is the unordered_map's
max_load_factor (library+0x48), not a library version float:
the 0x80-byte library object (0x28 mutex + 0x38 map + 0x20 name)
has no version field. PR #4028 recorded the same word as a
version float; the model and records here record the map field
instead.

## Evidence

- `records.json` — semantic records only. Instruction-level detail
  lives in the verbatim objdump excerpts; mnemonics such as
  `endbr64` are genuine instructions present in the target binary,
  not placeholders.
- `excerpts/` — 34 whole-function verbatim objdump files, produced by
  `export_excerpts.py` with
  `objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
  run from the repository root.
- `frames.txt` — the 34 FDE ranges, checked against a fresh frame dump.
- `callers.tsv` — every pinned routine's direct calls, tail jumps,
  lea references and RELATIVE addends, with the enclosing FDE.
- `relocations.txt` — the RELATIVE records for the five vtables, their
  typeinfos, the three object vtables, the register std::function
  GOT slots and the manager typeinfos, plus the typeinfo names.
- `census.py`, `export_excerpts.py`, `gen_records.py`, `verify.py` —
  the scripts that produced and check this packet.
- `MANIFEST.sha256` — SHA-256 of every packet file except itself.

## Verification

```
python3 research/work-items/RE-001-register-ttl-objects-115/verify.py
```

Checks: binary digest vs provenance, manifest, excerpt regeneration
byte-for-byte, every excerpt instruction byte-for-byte vs the raw
binary, three seeded random gate spots (`0x620558e`, `0x6202a4e`,
`0x620885c`) byte-for-byte vs a fresh objdump run and the raw binary,
frames, relocations, typeinfo names, literals, census reproduction,
records regeneration, the vtable map, the caller needles, and the
model tests (`tests/test_register_ttl_objects_115.py`,
129 checks). Prints `ALL CHECKS PASSED` on success.

## Model

`tools/register_ttl_objects_115.py` +
`tests/test_register_ttl_objects_115.py` (129 checks): the registry
with its libraries vector and name-to-entries map, the three entries
in registration order, `PatternEntry.matches` per the pinned
matcher, creator dispatch (MO / CFF / CF), the manager ops, the
pthread_once exactly-once semantics from both trigger entry points,
the out-slot install/replace contract, the count results, the
consumer constructions, and vector growth.

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so the
repository gates (`make verify`, `make test`, `make catalogue-check`)
cannot be run here; the packet's own `verify.py` is the check that
was run. The registry getter, the map helpers, the register helper,
the count function and the `PatternEntry` slots are cited from PRs
#4015, #3983 and #4028, not re-derived here (the register helper
and count bodies were re-read to pin their third/out arguments).

## Open unknowns

- The `TtlMergeOperator` / `TtlCompactionFilterFactory` /
  `TtlCompactionFilter` runtime methods (Merge, Filter,
  CreateCompactionFilter bodies beyond the C2 call, the options
  they expose) are not pinned here -- only construction and
  registration.
- The exact C++ names of the base vtables `0x64d93e0` and
  `0x64d3430` (installed by the ctor unwind paths) are not proven
  here; `0x64d3430` is shared with PR #4028's creator and is
  plausibly Configurable's vtable.
- The base destructor `0x5d35b50` (called by the CFF ctor's unwind
  path) is not pinned.
- The +0x08 field of the MergeOperator and CompactionFilterFactory
  objects is recorded as a `std::vector<std::string>` by shape
  (identical zeroing to the CompactionFilter's, whose unwind path
  proves the destruction loop); only the CompactionFilter's is
  proven.
- The out-slot indirection (the invoker loads `*(rdx)` as the slot
  address) means the create-host passes the out unique_ptr behind
  one more pointer level; the exact C++ type of that level is not
  pinned.
- ObjectRegistry +0x70..0x98 region (from PR #4015, still open).
