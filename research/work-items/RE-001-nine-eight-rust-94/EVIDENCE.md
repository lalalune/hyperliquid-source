# RE-001-nine-eight-rust-94: Two low-dword conditions with a clean full-RAX8/9 result

- Task/component: RE-001 / foundation; this is research allocation, not recovered ownership.
- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: node #94, Linux x86-64, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Scope: complete body `0x5229860..0x522987c` in ELF virtual-address coordinates and the explicitly stated value/data/call projection.
- New source: `src/node94-nine-eight/lib.rs`, independently authored MIT Rust, not copied from the unlicensed inferred reference.
- Status: static relation and finite separately compiled-Rust agreement. No original target execution, emulator, native ABI/fault equivalence or matched target bytes are claimed.

## Gap and bounded result

The base has a complete static packet but no independent Rust value
reconstruction at this source path. This dependency-free leaf implements the
whole value relation of `[0x5229860,0x522987c)`: return 8 when low32(RSI) == 1
and low32(RDI) == 4; return 9 otherwise. High argument bits are ignored.

The input tuple is `(RDI,RSI)`. For example `(0x100000004,0x100000001)`
returns8, just like `(4,1)`. The full returned RAX is clean 8 or 9; it is not
an AL-only contract. There are no outgoing calls or data loads in this body.
The existing packet's corrected actual instruction order and actual callers
are reused and authenticated, not replaced by its older inaccurate scout draft.

## Instruction/value argument

1. CMP1,ESI followed by SETE AL gives AL=A where A is0 or1 according to
   low32(RSI) == 1. Other EAX bits may still contain incoming values at this point.
2. XOR EDX,EDX then CMP4,EDI and SETE DL makes EDX=B, a clean0 or1, according
   to low32(RDI) == 4.
3. AND EAX,EDX produces EDX=A&B. Because EDX before that AND is0 or1,
   unknown EAX bits1..31 cannot affect it. Unknown incoming RAX upper bits
   therefore have no effect on the selected bit.
4. MOV9,EAX clears upper RAX and sets its low dword to9. SUB EDX,EAX gives
   exactly8 or9, still zero-extended to full RAX. Those are all four truth
   classes of the two low-dword equality predicates for every u64 input pair.
5. The Rust casts to u32 implement those same modulo2^32 argument
   projections. This instruction/value argument is written evidence, not a
   machine-checked formal proof or compiled-target byte-identity claim.
   Flags, other registers, calling ABI, ownership and caller intent are open.

## Independent pre-Rust observations

Before either Rust source file existed, authenticate the exact target, run
the existing bounded packet checker and freeze `admitted.json`, `admit.py`,
the independent Python oracle, the corpus and all source dependency hashes in
`ORACLE-FREEZE.json`. The freeze binds the original uncompressed logical
`vectors.tsv` bytes. Publication stores those same bytes losslessly as
`vectors.tsv.gz`; the verifier checks the decompressed bytes against that
unchanged frozen digest. `vectors.tsv` need not be written on disk to replay.

836 edge and seed-controlled pairs cover the four truth classes, neighboring
constants, high-bit arguments whose low dwords still equal1/4, dword wrap
boundaries and arbitrary u64 pairs. The independent Python relation partitions
the low-dword domains; the Rust implementation accepts inputs only. The written
instruction argument above explains why incoming partial-register residue is
masked out, without inventing an input register dependency in the Rust API.

`admit.py` pins the full capture and rechecks the existing packet without
changing it. It resolves selected VA ranges through actual file-backed ELF
sections, decodes the retained pcrel/sdata4 FDE ranges and raw CIE references,
and binds body/padding/unwind/call regions. For the insertion caller it also
resolves the PLT/GOT/JUMP_SLOT and dynamic symbol. The direct-caller byte scans
retain their original limited denominator; no complete indirect xref census
is inferred. Fresh whole-body GNU disassembly is retained separately.

## Compiled validation

Pinned rustc 1.94.1 / LLVM 21.1.8, edition 2021, opt-level 0 and opt-level 3:
836 observations match on each of two executions per level.
The rlib and input-only linked client repeat byte-for-byte at the same
optimization level. No target body is linked or transplanted. No root Cargo
workspace or invented dependency graph is introduced; builds invoke rustc
directly with no external Rust dependencies. Raw comparison outputs, command
streams, source/artifact hashes and the exact invocation options are retained
under `qualification/`.

Independent compiled mutation controls:

- `compare-full-width`: 8/836 observations differ, normal process exit.
- `disjoin-conditions`: 90/836 observations differ, normal process exit.
- `dirty-upper-rax`: 827/836 observations differ, normal process exit.

All 4 selected-region mutations reject below
the whole-capture digest check. An unselected-byte mutation deliberately passes
the selected-region check but fails the whole-capture check, retaining that
admission boundary. The verifier uses explicit checks that remain active under
Python `-O`. Finite observations and corruption controls are not a proof over
every memory state or compiler and do not supply a whole-node denominator.

## Reproduce and exact checks

From a prepared repository root, with pinned original inputs available:

```sh
python3 -O research/work-items/RE-001-nine-eight-rust-94/verify.py --rustc /path/to/rustc-1.94.1
rustfmt --edition 2021 --check src/node94-nine-eight/lib.rs src/node94-nine-eight/client.rs
python3 -O -m unittest discover -s tests -p 'test_foundation_nine_eight_gate.py' -v
```

These commands passed on a native Linux x86-64 tree at the stated base with
the independent additive packets. The focused predecessor file passed all
11 tests; the three related files together passed 46. Raw focused
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
