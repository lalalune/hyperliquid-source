# RE-001-insert-byte-counter-rust-94: Lazy byte comparison, external insertion projection and post-call counter

- Task/component: RE-001 / foundation; this is research allocation, not recovered ownership.
- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: node #94, Linux x86-64, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Scope: complete body `0x4fd6030..0x4fd607c` in ELF virtual-address coordinates and the explicitly stated value/data/call projection.
- New source: `src/node94-insert-byte-counter/lib.rs`, independently authored MIT Rust, not copied from the unlicensed inferred reference.
- Status: static relation and finite separately compiled-Rust agreement. No original target execution, emulator, native ABI/fault equivalence or matched target bytes are claimed.

## Gap and bounded result

The static predecessor specifies a selected flag and a final increment but
has no independently authored Rust caller. This reconstruction retains the
actual byte-read order, all four observed outgoing register values, the
post-call counter read and full fourth-pointer return. It does not implement
the external tree-rebalancing routine or claim that its contents are recovered.

The complete body is `[0x4fd6030,0x4fd607c)`. For an object in RDI, second
input in RSI, third pointer in RDX and fourth pointer in RCX, form
header=object+8. A nonzero second input or third==header selects flag1 and
does not read either key byte. Otherwise read third+0x20 first, then
fourth+0x20; select flag1 exactly when the latter unsigned byte is smaller.

The call to PLT0x5660550 receives `(flag,fourth,third,header)` in the observed
RDI/RSI/RDX/RCX projection. The PLT/GOT/JUMP_SLOT and dynamic symbol bytes
resolve to `_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_`.
This is a proven import name, not an identified implementation/library revision.
After a normal return, read the qword at object+0x28, add one modulo2^64,
store it there and return the full fourth pointer. The counter is read after
the opaque call; the API does not assume that the helper preserves it.
Names such as object/header/counter are descriptive, not recovered class types.

## Instruction/value argument

1. The prologue preserves incoming RCX in RBP and RDI in RBX. MOV EDI,1
   makes the default flag a clean64-bit1, and LEA sets RCX=object+8.
2. TEST RSI bypasses byte reads when second is nonzero. Otherwise CMP RDX,RCX
   bypasses them on equality. In the remaining arm XOR EDI,EDI clears all
   flag bits; MOVZBL reads third+0x20; CMPB reads fourth+0x20 and subtracts the
   third byte. SETB DIL is1 exactly for unsigned fourth_byte<third_byte.
   Both branches therefore supply a clean full flag0 or1.
3. MOV RBP,RSI forwards the original fourth pointer. RDX and RCX retain third
   and header. The target is the authenticated PLT entry whose unique
   R_X86_64_JUMP_SLOT names the insert-and-rebalance symbol. Runtime dynamic
   binding, its implementation, tree invariants and transitive effects remain
   unproved. The Rust callback represents that boundary explicitly.
4. ADDQ1 at object+0x28 occurs only after the call returns. The new safe view
   reads the current qword after its callback and writes wrapping_add(1).
   This models ordinary word state, not a hardware-atomic RMW, bus accesses,
   concurrency or fault timing. A callback can supply changed counter bytes;
   a pre-call cached value is not a sound replacement without another premise.
5. MOV RBP,RAX returns all64 bits of the original fourth pointer, independent
   of the callback's RAX. Other registers, native ABI/unwinding and behavior
   when the external call fails to return remain excluded.

## Independent pre-Rust observations

Before either Rust source file existed, authenticate the exact target, run
the existing bounded packet checker and freeze `admitted.json`, `admit.py`,
the independent Python oracle, the corpus and all source dependency hashes in
`ORACLE-FREEZE.json`. The freeze binds the original uncompressed logical
`vectors.tsv` bytes. Publication stores those same bytes losslessly as
`vectors.tsv.gz`; the verifier checks the decompressed bytes against that
unchanged frozen digest. `vectors.tsv` need not be written on disk to replay.

66,131 fixtures include all 65,536 ordered unsigned-byte pairs on distinct
addresses, high-bit/wrapping pointers, equality/nonzero bypass arms, aliases,
counter wrap, seeded states and refusal controls. The fixture initializes
counter bytes, third key byte, then fourth key byte, so an alias is resolved
by actual last-written bytes. Selected spans are removed afterwards. The
opaque callback optionally replaces the counter before the library's later
read. Its configured side effect is a boundary test, not an assertion that
the actual imported helper changes that word. Counter presence/state and all
reached abstract operations/arguments are compared. The view's refused store
and callback behavior do not specify hardware fault or exception behavior.

`admit.py` pins the full capture and rechecks the existing packet without
changing it. It resolves selected VA ranges through actual file-backed ELF
sections, decodes the retained pcrel/sdata4 FDE ranges and raw CIE references,
and binds body/padding/unwind/call regions. For the insertion caller it also
resolves the PLT/GOT/JUMP_SLOT and dynamic symbol. The direct-caller byte scans
retain their original limited denominator; no complete indirect xref census
is inferred. Fresh whole-body GNU disassembly is retained separately.

## Compiled validation

Pinned rustc 1.94.1 / LLVM 21.1.8, edition 2021, opt-level 0 and opt-level 3:
66,131 observations match on each of two executions per level.
The rlib and input-only linked client repeat byte-for-byte at the same
optimization level. No target body is linked or transplanted. No root Cargo
workspace or invented dependency graph is introduced; builds invoke rustc
directly with no external Rust dependencies. Raw comparison outputs, command
streams, source/artifact hashes and the exact invocation options are retained
under `qualification/`.

Independent compiled mutation controls:

- `signed-byte-comparison`: 32,860/66,131 observations differ, normal process exit.
- `counter-read-before-helper`: 66,102/66,131 observations differ, normal process exit.
- `saturating-counter`: 330/66,131 observations differ, normal process exit.
- `swapped-helper-pointers`: 66,066/66,131 observations differ, normal process exit.
- `truncate-return-pointer`: 265/66,131 observations differ, normal process exit.

All 10 selected-region mutations reject below
the whole-capture digest check. An unselected-byte mutation deliberately passes
the selected-region check but fails the whole-capture check, retaining that
admission boundary. The verifier uses explicit checks that remain active under
Python `-O`. Finite observations and corruption controls are not a proof over
every memory state or compiler and do not supply a whole-node denominator.

## Reproduce and exact checks

From a prepared repository root, with pinned original inputs available:

```sh
python3 -O research/work-items/RE-001-insert-byte-counter-rust-94/verify.py --rustc /path/to/rustc-1.94.1
rustfmt --edition 2021 --check src/node94-insert-byte-counter/lib.rs src/node94-insert-byte-counter/client.rs
python3 -O -m unittest discover -s tests -p 'test_foundation_byte_gate_counter.py' -v
```

These commands passed on a native Linux x86-64 tree at the stated base with
the independent additive packets. The focused predecessor file passed all
18 tests; the three related files together passed 46. Raw focused
logs are retained under `checks/`. They are checker/model tests, not target
execution. Rustfmt passed on the exact qualified source bytes. The coordinator also
recorded `make doctor verify catalogue-check` and `make reproduce` exit0 on
the shared exact base with the independent additive packets. A bounded
`timeout --signal=TERM --kill-after=10s 90s make test` ended124: 9/971 files
started, eight reported completion with247 tests and no failure summaries.
This is not a whole-suite pass or a complete per-head run. Exact sanitized
common logs and results are retained in `checks/`. Hosted CI and container
success are unclaimed.

The coordinator independently checked frozen, source and qualifier hashes,
compared every row of all four raw primary outputs, inspected fresh target
disassembly and the library source, and replayed a hash-bound compiled sample.
The record for this packet is retained in `checks/parent-validation.json`.
This is internal validation evidence, not a submitted GitHub review.

## Remaining gaps

Runtime object meaning and ownership, full native calling/layout/fault/unwind
behavior, arbitrary reentry/concurrency, library and helper closure where
opaque, target compiled-byte identity, whole-program data/relocation closure
and the integrated node remain open. Safe missing-view refusals are new API
outcomes; noncanonical numeric addresses are algebraic fixtures. No progress
gate, ownership attribution or matched-byte count changes. No live services,
chain action, private data or networked target operation is part of this work.

Next step: review this explicit projection and its assumptions before composing
the fragment into a native implementation. Do not use a field label as a source
type or a completed-component claim.
