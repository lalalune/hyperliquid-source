# RE-001: pin node #115 the SystemClock registry factory dispatch 0x5fd4080 and its name lookup 0x5fd3d00

## Task and bounded question

Task **RE-001** (the node #115 function map). What does the sibling
registry factory dispatch `0x5fd4080` do — the SystemClock dispatch listed
as an open unknown in #4428 — how does its name lookup `0x5fd3d00`
resolve a clock name in the registry, and which code writes a non-kOk
Status into the dispatch's `0x30(%rsp)` temp (also open in #4428)?
Resolves #4428's open unknowns: "the sibling dispatches at
`0x5fd4080..0x5fd4627` and `0x6136b40..0x613721b`" (the first of the two)
and "which factory writes a non-kOk Status into the dispatch's
`0x30(%rsp)` temp".

## Answer

`0x5fd4080` is the SystemClock registry factory dispatch with signature
`(Status* out, ObjectRegistry* registry, const std::string& name,
shared_ptr<SystemClock>* clock_slot)` — the same template as #4428's
BlockCipher dispatch `0x5ff9fe0`, instantiated for the `"SystemClock"`
factory type. Its only caller is the dispatcher `0x5fd46c0` at
`0x5fd4aa3`.

- **Lookup.** It resolves the name through `0x5fd3d00`, which locks the
  registry mutex (`+0x98`), walks the libraries vector (`+0x00`/`+0x08`)
  backwards, and per library locks its mutex (`+0x00`) and queries its map
  at `+0x28` for `"SystemClock"` via `0x5fd2980`. The key is built on the
  stack SSO: `movabs "SystemCl"` at `0x5fd3da5` plus `"lock"`
  (`0x6b636f6c`) at `0x5fd3dc1`, 11 chars. The first candidate whose vtable
  slot 2 (`Matches`, forwarding to PatternEntry Matches `0x61f8670`)
  accepts the name wins; the factory record is cloned (manager op 2, a
  no-op here, plus the explicit 16-byte copy of the `{manager, invoker}`
  pair) into the 32-byte out record. On exhaustion it recurses into the
  parent registry at `+0x60`; with no parent the record is zeroed.
- **Factory call.** The matched creator is invoked through the record's
  `+0x18` invoker as `factory(record, name, &slot, &string)`. The creator
  stores the new raw object pointer at the slot (`0x28(%rsp)` in the
  dispatch) and returns it; a null return means failure. The fourth
  argument is a string the factory may fill with an error message.
- **Outcomes.** Lookup miss: `kNotSupported` (code 3) `"Could not load
  SystemClock: <name>"` (built into the `0x30(%rsp)` temp at `0x5fd44be`,
  then move-assigned into `*out` by the shared tail). Factory returns
  null with the string arg left empty: `kInvalidArgument` (code 4), same
  message (`0x5fd43d7`). Factory returns null but filled the string arg:
  `kInvalidArgument` `"<factory message>: <name>"` (`0x5fd441f`).
  Factory returns non-null but stores nothing: `kInvalidArgument`
  `"Cannot make a shared SystemClock from unguarded one : <name>"`
  (`0x5fd42e4`, built directly into `*out`). Success: a fresh 0x18-byte
  non-inplace shared_ptr control block (vtable `0x64cdf38`, typeinfo
  `St15_Sp_counted_ptrIPN7rocksdb11SystemClockELN9__gnu_cxx12_
  Lock_policyE2EE`, counts `(1,1)` from `0x459b20`, object at `+0x10`) is
  stored into the out clock slot, the old clock is released via
  `0x5d350c0`, and `*out = kOk`.
- **The temp Status.** No factory writes the `0x30(%rsp)` temp — this
  resolves #4428's open unknown. The dispatch itself builds the temp
  Status in the factory-null branches (`0x5fd43d7`, `0x5fd441f`) and the
  lookup-miss branch (`0x5fd44be`), then the shared tail at `0x5fd414b`
  move-assigns it into `*out` via `0x5fcdf70` at `0x5fd432c` when its code
  byte is non-zero. The same template holds in #4428: there the temp is
  built at `0x5ffa3d9` and the shared tail is `0x5ffa0af`.
- **Dispatcher and wrapper.** The dispatcher `0x5fd46c0` (FDE
  `0x5fd46c0..0x5fd4c2e`, cited) calls the options-map host `0x609e510`
  at `0x5fd489a`, this dispatch at `0x5fd4aa3`, and configure `0x609e2d0`
  at `0x5fd4b76` — mirroring #4402's dispatcher `0x5ffa710`. The wrapper
  `0x5fd4c30` (FDE `0x5fd4c30..0x5fd4cc1`, cited) applies the same `"id"`
  gate as #4402's wrapper `0x5ffae10` (`rcx+0x08 == 2`, string starts
  with `"id"`, `r8+0x08 == 0` → zero the shared_ptr, else forward to the
  dispatcher at `0x5fd4c60`).
- **Registration lead.** The only other binary-wide lea of
  `"SystemClock"` (`0x5fd2298`) sits in `0x5fd20d0`, which also builds
  `"TimeEmulatedSystemClock"` (literal `0x4372ae`) and calls the register
  helper `0x5fd1da0` (22 E8 callers binary-wide) — plausibly the
  TimeEmulatedSystemClock registration. The creator routine it registers
  is not pinned here.
- **Vtable note.** The SystemClock control-block vtable `0x64cdf38` has
  exactly 5 function slots. Unlike the BlockCipher vtable `0x64d0198`
  (#4428), which has a trailing zero slot, the qword after slot 4 here
  is a RELATIVE reloc to the `"DEBUG"` string table at `0x446560` — the
  next `.data.rel.ro` object, not part of this vtable.

## Evidence

- `records.json` — semantic records only. Instruction-level detail lives
  in the verbatim objdump excerpts; mnemonics such as `endbr64` are
  genuine instructions present in the target binary, not placeholders.
- `fn-5fd3d00.objdump.txt`, `fn-5fd4080.objdump.txt` — whole-function
  verbatim objdump excerpts, produced by `export_excerpts.py` with
  `objdump -d --start-address=<start> --stop-address=<stop>
  work/hl-node-115.bin` run from the repository root.
- `frames.txt` — the FDE ranges for the two pinned functions and the
  cited helpers, checked against a fresh frame dump.
- `callers.tsv` — every pinned routine's direct calls and lea references
  with the enclosing FDE (full binary-wide census for the
  `"Cannot make a shared "`, `"Could not load "` and `"SystemClock"`
  literals; in-packet sites for `" from unguarded one "`).
- `literals.tsv`, `vtables.tsv` — the error-message literals and the
  SystemClock control-block vtable (5 slots + typeinfo).
- `census.py`, `export_excerpts.py`, `gen_records.py`, `verify.py` — the
  scripts that produced and check this packet.
- `MANIFEST.sha256` — SHA-256 of every packet file except itself.

## Verification

```
python3 research/work-items/RE-001-system-clock-dispatch-115/verify.py
```

Checks: binary digest vs provenance, manifest, excerpt regeneration
byte-for-byte, frames, raw-binary spot bytes, literals, lea/E8 censuses,
the control-block vtable slots + typeinfo, records regeneration, and the
model tests (`tests/test_system_clock_dispatch_115.py`, 22 checks).

## Model

`tools/system_clock_dispatch_115.py` +
`tests/test_system_clock_dispatch_115.py` (22 checks): the Status
message join (`msg1 + ": " + msg2`), the five dispatch outcomes
(miss / factory-null / factory-null-with-message / unguarded / success),
the lookup walk with parent recursion, the manager ops (op 2 clone,
op 3 destroy), the control-block layout, and the dispatcher/wrapper
identities. The fixture library uses an exact-match
`"TimeEmulatedSystemClock"` creator to exercise the dispatch; the
registered SystemClock creators are not pinned, so the fixture is a
model exercise, not a binary claim.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify`, `make test` and `make catalogue-check` could not be run in a
tooled environment; the packet's own `verify.py` and the model tests
(22 checks) were run instead. The binary is the local materialized
node #115 (`work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
from `provenance/artifacts.json`).

## Open unknowns

- The registered SystemClock creators: which factory routines back the
  `"SystemClock"` entries (`0x5fd20d0` builds `"TimeEmulatedSystemClock"`
  and calls the register helper `0x5fd1da0`, but the creator routine
  itself is not pinned).
- The libraries vector element's second qword (the lookup reads only the
  first qword, the library pointer).
- The library object's fields at `+0x08..+0x27` (mutex at `+0x00`, map
  at `+0x28`).
- The map value's owning type (`0x5fd2980` returns the entry whose
  `+0x28`/`+0x30` candidate vector the lookup walks).
- The control-block vtable slots 0..4 method identities.
- The remaining sibling dispatch at `0x6136b40..0x613721b` (same
  `"Cannot make a shared "` / `"Could not load "` literals, another
  factory type).
- The dispatcher `0x5fd46c0` internals (cited only) and the wrapper
  `0x5fd4c30`'s caller (no direct E8 caller binary-wide; reached through
  a function-pointer table, as in #4402).
