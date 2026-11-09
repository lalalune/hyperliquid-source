# RE-001: pin node #115 the registry factory dispatch 0x5ff9fe0 and its BlockCipher name lookup 0x5ff9c60

## Task and bounded question

Task **RE-001** (the node #115 function map). What does the registry
factory dispatch `0x5ff9fe0` do — the BlockCipher dispatch cited (not
pinned) by #4402 — how does its name lookup `0x5ff9c60` resolve a provider
name in the registry, and why do two byte-similar dispatcher/wrapper pairs
exist (#4402's open unknown)? Resolves #4402's open unknowns: "0x5ff9fe0
internals", "why two byte-identical dispatcher/wrapper pairs exist", and
the ConfigOptions `+0x40` field identity.

## Answer

`0x5ff9fe0` is the BlockCipher registry factory dispatch with signature
`(Status* out, ObjectRegistry* registry, const std::string& name,
shared_ptr<BlockCipher>* cipher_slot)`. Its only caller is the dispatcher
`0x5ffa710` at `0x5ffa962` (#4402); the dispatcher passes the registry as
`opts+0x40`.

- **Lookup.** It resolves the name through `0x5ff9c60`, which locks the
  registry mutex (`+0x98`), walks the libraries vector (`+0x00`/`+0x08`)
  backwards, and per library locks its mutex (`+0x00`) and queries its map
  at `+0x28` for `"BlockCipher"` via `0x5fd2980`. The first candidate whose
  vtable slot 2 (`Matches`, forwarding to PatternEntry Matches `0x61f8670`)
  accepts the name wins; the factory record is cloned (manager op 2, a
  no-op here, plus the explicit 16-byte copy of the `{manager, invoker}`
  pair) into the 32-byte out record. On exhaustion it recurses into the
  parent registry at `+0x60`; with no parent the record is zeroed.
- **Factory call.** The matched creator is invoked through the record's
  `+0x18` invoker as `factory(record, name, &slot, &empty_string)`. The
  creator stores the new raw object pointer at the slot and returns it
  (the ROT13 creator `0x5ff7120` does this at `0x5ff729a`, destroying any
  previous object through its vtable slot 1); a null return means failure.
- **Outcomes.** Lookup miss: `kNotSupported` (code 3) `"Could not load
  BlockCipher: <name>"`. Factory returns null: `kInvalidArgument`
  (code 4), same message. Factory returns non-null but stores nothing:
  `kInvalidArgument` `"Cannot make a shared BlockCipher from unguarded
  one : <name>"` (note the space before the colon: the message is
  `"Cannot make a shared " + "BlockCipher" + " from unguarded one "` plus
  `": " + name` by the Status ctor `0x61cf670`). Success: a fresh
  0x18-byte non-inplace shared_ptr control block (vtable `0x64d0198`,
  typeinfo `St15_Sp_counted_ptrIPN7rocksdb11BlockCipherELN9__gnu_cxx12_
  Lock_policyE2EE`, counts `(1,1)` from `0x459b20`, object at `+0x10`) is
  stored into the out cipher slot, the old cipher is released via
  `0x5d350c0`, and `*out = kOk`.
- **The twins.** The pairs are parallel instantiations of the same
  template, one per factory type — this corrects #4402's "byte-identical"
  note. The dispatcher `0x5ffa710` calls `0x5ff9fe0` (BlockCipher) while
  the twin dispatcher `0x5ffba10` calls `0x5ffb250`
  (EncryptionProvider) at `0x5ffbc62`; the twin lookup `0x5ffaeb0` queries
  `"EncryptionProvider"` (18 chars, heap-backed: 16 bytes from literal
  `0x4539b0` via `movdqa` plus `"er"` `0x7265`) instead of `"BlockCipher"`.
- **ConfigOptions+0x40.** It is a `std::shared_ptr<ObjectRegistry>`
  (object at `+0x40`, control block at `+0x48`), built by the default
  init `0x60bb890` through `0x61f9400`, which allocates a fresh 0xd0-byte
  registry from the getter `0x61f92b0` (PR #4015).

## Evidence

- `records.json` — semantic records only. Instruction-level detail lives
  in the verbatim objdump excerpts; mnemonics such as `endbr64` are
  genuine instructions present in the target binary, not placeholders.
- `fn-5ff9c60.objdump.txt`, `fn-5ff9fe0.objdump.txt`,
  `fn-5ffaeb0.objdump.txt`, `fn-5ffb250.objdump.txt` — whole-function
  verbatim objdump excerpts, produced by `export_excerpts.py` with
  `objdump -d --start-address=<start> --stop-address=<stop>
  work/hl-node-115.bin` run from the repository root.
- `frames.txt` — the FDE ranges for the four pinned functions and the
  cited helpers, checked against a fresh frame dump.
- `callers.tsv` — every pinned routine's direct calls and lea references
  with the enclosing FDE (full binary-wide census for the
  `"Cannot make a shared "`, `"BlockCipher"`, `"Could not load "` and
  `"EncryptionProvider"` literals; in-packet sites for the shared
  `" from unguarded one "` and `"basic_string::append"` literals).
- `literals.tsv`, `vtables.tsv` — the error-message literals and the
  BlockCipher control-block vtable (5 slots + typeinfo).
- `census.py`, `export_excerpts.py`, `gen_records.py`, `verify.py` — the
  scripts that produced and check this packet.
- `MANIFEST.sha256` — SHA-256 of every packet file except itself.

## Verification

```
python3 research/work-items/RE-001-registry-factory-dispatch-115/verify.py
```

Checks: binary digest vs provenance, manifest, excerpt regeneration
byte-for-byte, frames, raw-binary spot bytes, literals, lea/E8 censuses,
the control-block vtable slots + typeinfo, the three manager typeinfo
addresses, records regeneration, and the model tests
(`tests/test_registry_factory_dispatch_115.py`, 28 checks). Prints
`108/108 checks passed` on success.

## Model

`tools/registry_factory_dispatch_115.py` +
`tests/test_registry_factory_dispatch_115.py` (28 checks): the Status
message join (`msg1 + ": " + msg2`), the four dispatch outcomes
(miss / factory-null / unguarded / success), the lookup walk with
parent recursion, the three registered creators' pattern matches
(CTR / 1://test / ROT13), the manager ops (0 = typeinfo, 1 = clone,
2/3 = no-op), the control-block layout, and the twin type names.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify`, `make test` and `make catalogue-check` could not be run in a
tooled environment; the packet's own `verify.py` (107 checks) and the
model tests (28 checks) were run instead. The binary is the local
materialized node #115 (`work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
from `provenance/artifacts.json`).

## Open unknowns

- Which factory writes a non-kOk Status into the dispatch's `0x30(%rsp)`
  temp (the `0x5ffa2c0` move-assign path is defensive; no registered
  creator writes it).
- The libraries vector element's second qword (the lookup reads only the
  first qword, the library pointer).
- The library object's fields at `+0x08..+0x27` (mutex at `+0x00`, map at
  `+0x28`).
- The map value's owning type (`0x5fd2980` returns the entry whose
  `+0x28`/`+0x30` candidate vector the lookup walks).
- The control-block vtable slots 0..4 method identities.
- The sibling dispatches at `0x5fd4080..0x5fd4627` and
  `0x6136b40..0x613721b` (same `"Cannot make a shared "` /
  `"Could not load "` literals, other factory types).
- The twin dispatch's second release site `0x5ffb406` (the BlockCipher
  dispatch has one, `0x5ffa14b`).
