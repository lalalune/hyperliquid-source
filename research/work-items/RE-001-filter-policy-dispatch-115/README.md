# RE-001: pin node #115 the FilterPolicy registry factory dispatch 0x6136b40 and its name lookup 0x6136650

## Task and bounded question

Task **RE-001** (the node #115 function map). What does the remaining
sibling registry factory dispatch `0x6136b40` do — the FilterPolicy
dispatch listed as an open unknown in #4428 and #4453 — and how does its
name lookup `0x6136650` resolve a policy name in the registry? Resolves
#4428's open unknown: "the sibling dispatch `0x6136b40..0x613721b`" (the
second of the two; the first was pinned by #4453).

## Answer

`0x6136b40` is the FilterPolicy registry factory dispatch with signature
`(Status* out, ObjectRegistry* registry, const std::string& name,
shared_ptr<const FilterPolicy>* policy_slot)` — the same template as
#4428's BlockCipher dispatch `0x5ff9fe0` and #4453's SystemClock dispatch
`0x5fd4080`, instantiated for the `"FilterPolicy"` factory type. Its only
caller is the dispatcher `0x6137290` at `0x61374a0`.

- **Lookup.** It resolves the name through `0x6136650`, which locks the
  registry mutex (`+0x98`), walks the libraries vector (`+0x00`/`+0x08`)
  backwards, and per library locks its mutex (`+0x00`) and queries its map
  at `+0x28` for `"FilterPolicy"`. The key is built on the stack SSO:
  `movabs "FilterPo"` at `0x61366cd` plus `"licy"` (`0x7963696c`) at
  `0x61366e0`, 12 chars. The first candidate whose vtable slot 2
  (`Matches`, forwarding to PatternEntry Matches `0x61f8670`) accepts the
  name wins; the factory record is cloned (manager op 2, a no-op here,
  plus the explicit 16-byte copy of the `{manager, invoker}` pair) into
  the 32-byte out record. On exhaustion it recurses into the parent
  registry at `+0x60`; with no parent the record is zeroed.
- **Factory call.** The matched creator is invoked through the record's
  `+0x18` invoker as `factory(record, name, &slot, &string)`. The creator
  stores the new raw object pointer at the slot (`0x28(%rsp)` in the
  dispatch) and returns it; a null return means failure. The fourth
  argument is a string the factory may fill with an error message.
- **Outcomes.** Lookup miss: `kNotSupported` (code 3) `"Could not load
  FilterPolicy: <name>"` (built into the `0x30(%rsp)` temp at `0x6137021`,
  then copied into `*out` by the shared tail). Factory returns null with
  the string arg left empty (`0x88(%rsp) == 0`): `kInvalidArgument`
  (code 4), same message (`0x6136f0a`). Factory returns null but filled
  the string arg: `kInvalidArgument` `"<factory message>: <name>"`
  (`0x6136f59`; msg1 is the factory's string as a `{ptr,size}`
  string_view at `0x40(%rsp)`). Factory returns non-null but stores
  nothing: `kInvalidArgument` `"Cannot make a shared FilterPolicy from
  unguarded one : <name>"` (`0x6136e05`, built directly into `*out`;
  the unguarded object is then destroyed through its vtable slot 1 at
  `0x6136ce4`). Success: a fresh 0x18-byte non-inplace shared_ptr
  control block (vtable `0x64d37f0`, typeinfo
  `St15_Sp_counted_ptrIPKN7rocksdb12FilterPolicyELN9__gnu_cxx12_
  Lock_policyE2EE`, counts `(1,1)` from `0x459b20`, object at `+0x10`)
  is stored into the out policy slot, the old policy is released via
  `0x5d350c0`, and `*out = kOk`.
- **The temp Status.** No factory writes the `0x30(%rsp)` temp — the
  same answer #4453 gave for the SystemClock dispatch. The dispatch
  itself builds the temp Status in the factory-null branches
  (`0x6136f0a`, `0x6136f59`) and the lookup-miss branch (`0x6137021`),
  then the shared tail at `0x6136e30` copies it into `*out` when its code
  byte is non-zero.
- **Template differences from the siblings.** (1) The lookup inlines the
  unordered_map find: there is no call to the map-find helper `0x5fd2980`
  anywhere in `0x6136650..0x6136b35`. If the map holds more than `0x14`
  entries it hashes (`_Hash_bytes`, seed `0xc70f6907`, bucket count at
  `+0x30`, bucket array at `+0x28`, chain walk with hash + size +
  `memcmp`); otherwise it walks the node list linearly from the head at
  `+0x38`, comparing the 12-byte key by length then bytes. (2) The shared
  tail copies the 16-byte temp Status inline (`movzwl`/`mov`/`mov` at
  `0x6136e30..0x6136e48`) instead of calling the Status move-assign helper
  `0x5fcdf70` — there is no call to `0x5fcdf70` anywhere in
  `0x6136b40..0x613721b`. The BlockCipher dispatch shares the inline tail;
  the SystemClock dispatch calls the helper.
- **Control block.** The typeinfo names a `shared_ptr<const
  rocksdb::FilterPolicy>` (`IPK...`): the out slot holds a const
  pointee, unlike the BlockCipher/SystemClock slots. The vtable
  `0x64d37f0` has 5 function slots plus a trailing zero slot, like the
  BlockCipher vtable `0x64d0198` (#4428).
- **String ctor copy.** The dispatch builds its strings through
  `0x612f730`, a second copy of the `std::string(const char*)` ctor whose
  first 16 bytes are identical to `0x5fcd890`'s (the copy the sibling
  dispatches call). FDE `0x612f730..0x612f813`.
- **Dispatcher and wrapper.** The dispatcher `0x6137290` (FDE
  `0x6137290..0x6137688`, cited) calls the options-map host `0x609e510`
  at `0x61373eb`, pthread_once-inits the provider registry map
  `0x6507c78` with init `0x6138a10` at `0x6137457`, this dispatch at
  `0x61374a0`, and configure `0x609e2d0` at `0x61374e7` — mirroring
  #4402's dispatcher `0x5ffa710`. The wrapper `0x60dafb0` (FDE
  `0x60dafb0..0x60db041`, cited) applies the same `"id"` gate as #4402's
  wrapper `0x5ffae10` (`rcx+0x08 == 2`, string starts with `"id"`,
  `r8+0x08 == 0` → zero the shared_ptr, else forward to the dispatcher
  at `0x60dafe0`).
- **Registration lead.** The only other binary-wide lea sites of
  `"FilterPolicy"` are `0x6138179` (inside the builtin registrar
  `0x6137fe0`) and `0x6137b6c` (inside the per-factory registrar
  `0x6137810`). `0x6137fe0` is called from the dispatcher's pthread_once
  init `0x6138a10`; it registers `"FilterPolicy"` via the register helper
  `0x5fd1da0` at `0x613818f`, then calls `0x6137810` three times
  (`0x613825f`, `0x6138356`, `0x6138450`) with names built from literals
  including `":false"` (`0x442ac3`) and `":true"` (`0x4384f5`) suffixes
  — plausibly BloomFilterPolicy-style registrations. `0x6137810`
  allocates a 0x30-byte record (vtable `0x64d5390`) and registers
  `"FilterPolicy"` via `0x5fd1da0` at `0x6137b87`. The creator routines
  themselves are not pinned.

## Verification

`verify.py` reports ALL CHECKS PASSED (88/88: artifact digest, manifest,
excerpt regeneration, FDEs, raw-binary spot bytes, literals, lea census,
E8 census — including the two negative checks that `0x5fd2980` and
`0x5fcdf70` have no in-packet caller — vtable slots + typeinfo,
semantic-only records, model tests). `pytest` passes the model tests
(22 passed).

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify`, `make test` and `make catalogue-check` were not run in a tooled
environment; the packet's own `verify.py` (which re-checks the binary
bytes, the FDEs, the censuses and the model tests) was run instead and
passes. The evidence is bound to node #115 (`work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
from `provenance/artifacts.json`).

## Open unknowns

- The registered FilterPolicy creators (which factory routines back the
  `"FilterPolicy"` entries; `0x6137fe0` builds `":false"` / `":true"`
  suffixed names but the creator routines are not pinned).
- The libraries vector element's second qword; the library object's
  fields at `+0x08..+0x27`; the map value's owning type.
- The control-block vtable slots 0..4 method identities.
- The dispatcher `0x6137290` internals and the wrapper `0x60dafb0`'s
  caller.
- The base names the registrar `0x6137fe0` builds before the `":false"`
  / `":true"` suffixes.
