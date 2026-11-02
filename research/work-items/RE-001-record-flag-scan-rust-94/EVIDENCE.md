# RE-001-record-flag-scan-rust-94: Full-RAX record flag scan with its conditional tagged call

- Task/component: RE-001 / foundation; this is research allocation, not recovered ownership.
- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: node #94, Linux x86-64, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Scope: complete body `0x3bde0b0..0x3bde10b` in ELF virtual-address coordinates and the explicitly stated value/data/call projection.
- New source: `src/node94-record-flag-scan/lib.rs`, independently authored MIT Rust, not copied from the unlicensed inferred reference.
- Status: static relation and finite separately compiled-Rust agreement. No original target execution, emulator, native ABI/fault equivalence or matched target bytes are claimed.

## Gap and bounded result

The existing static packet records the AL predicate, but its fast-call note
says that `mov al,1` overwrites RAX. The actual instruction overwrites only
the low byte. This independent Rust reconstruction preserves the full RAX
continuation and reached reads, rather than returning a fabricated clean
boolean on every path. It adds no source-level meaning for the records.

The complete body is `[0x3bde0b0,0x3bde10b)`. Load the count qword from
object+0x10. An unsigned count at least 10001 takes the call arm: place the
little-endian tag bytes `43 01` in the temporary and call 0x3c1ada0. If that
callee returns normally with RAX=c, the continuation returns `(c & ~255)|1`.
The body does not establish that the callee returns normally, its source
signature, implementation or effects. The safe callback exposes only the
established target/tag event and post-call RAX. It is not a native stack ABI.

For count n below 10001, load the record pointer from object+8, including
when n=0. Scan byte pointer+0x4e with stride0x50 and stop at the first zero.
Let `prefix=(16*n)&~255`. The full result is prefix on an early zero and
prefix|1 after all n bytes are nonzero. With n=16, these are256 and257;
the AL predicate alone is0 and1. Pointer arithmetic wraps as u64 in the
view; no arbitrary numeric address is dereferenced by the host.

## Instruction/value argument

1. `mov 0x10(%rdi),%rax` supplies the unsigned count. The unsigned JB after
   CMP10001 selects exactly 0<=n<10001 for the scan arm.
2. That arm loads RCX from object+8 before testing the scan length, so an empty
   scan still reaches the pointer-slot read. SHL4 gives RAX=16n and LEA gives
   RDX=80n, without overflow in this bounded count domain.
3. At the loop header TEST RDX sets ZF and SETE replaces only AL. RDX is
   decremented by80 before each byte comparison. A nonzero byte branches to
   the header; a zero falls through to RET with AL=0. Exhaustion reaches
   SETE with RDX=0 and AL=1. No instruction changes RAX bits8..63 afterwards.
4. Therefore the scan relation is `(16n & ~255)|all_nonzero`. The for-loop
   implementation reaches the same byte addresses and stops at the same
   first zero under stable ordinary view reads. For a missing reached byte,
   the new safe API refuses; native fault delivery is not reconstructed.
5. On the other arm MOVW establishes the two tag bytes, the direct rel32
   names0x3c1ada0, and MOV AL,1 preserves that callback return's upper bits.
   This is a conditional continuation theorem, not callee closure or a proof
   of normal return. RSI/RDX/other input registers, physical stack storage,
   flags and caller intent remain outside the API projection.

## Independent pre-Rust observations

Before either Rust source file existed, authenticate the exact target, run
the existing bounded packet checker and freeze `admitted.json`, `admit.py`,
the independent Python oracle, the corpus and all source dependency hashes in
`ORACLE-FREEZE.json`. The freeze binds the original uncompressed logical
`vectors.tsv` bytes. Publication stores those same bytes losslessly as
`vectors.tsv.gz`; the verifier checks the decompressed bytes against that
unchanged frozen digest. `vectors.tsv` need not be written on disk to replay.

422 finite fixtures include empty/single/early-zero scans, count 16 upper-bit
returns, count 10000/10001 transition, unsigned high counts, seeded flags and
wrapping addresses, missing reached spans and callback refusal. The fixture
maps count and pointer words, then the finite flags, then removes selected
spans. The Python dictionary and Rust BTreeMap read the resulting actual bytes.
The fast path has no flag/pointer reads; the slow empty path still reads the
pointer slot. Callback refusal is a new safe outcome, not a native exception.

`admit.py` pins the full capture and rechecks the existing packet without
changing it. It resolves selected VA ranges through actual file-backed ELF
sections, decodes the retained pcrel/sdata4 FDE ranges and raw CIE references,
and binds body/padding/unwind/call regions. For the insertion caller it also
resolves the PLT/GOT/JUMP_SLOT and dynamic symbol. The direct-caller byte scans
retain their original limited denominator; no complete indirect xref census
is inferred. Fresh whole-body GNU disassembly is retained separately.

## Compiled validation

Pinned rustc 1.94.1 / LLVM 21.1.8, edition 2021, opt-level 0 and opt-level 3:
422 observations match on each of two executions per level.
The rlib and input-only linked client repeat byte-for-byte at the same
optimization level. No target body is linked or transplanted. No root Cargo
workspace or invented dependency graph is introduced; builds invoke rustc
directly with no external Rust dependencies. Raw comparison outputs, command
streams, source/artifact hashes and the exact invocation options are retained
under `qualification/`.

Independent compiled mutation controls:

- `lose-slow-rax-prefix`: 107/422 observations differ, normal process exit.
- `lose-fast-rax-prefix`: 18/422 observations differ, normal process exit.
- `wrong-fast-threshold`: 3/422 observations differ, normal process exit.
- `skip-empty-pointer-read`: 24/422 observations differ, normal process exit.

All 7 selected-region mutations reject below
the whole-capture digest check. An unselected-byte mutation deliberately passes
the selected-region check but fails the whole-capture check, retaining that
admission boundary. The verifier uses explicit checks that remain active under
Python `-O`. Finite observations and corruption controls are not a proof over
every memory state or compiler and do not supply a whole-node denominator.

## Reproduce and exact checks

From a prepared repository root, with pinned original inputs available:

```sh
python3 -O research/work-items/RE-001-record-flag-scan-rust-94/verify.py --rustc /path/to/rustc-1.94.1
rustfmt --edition 2021 --check src/node94-record-flag-scan/lib.rs src/node94-record-flag-scan/client.rs
python3 -O -m unittest discover -s tests -p 'test_foundation_all_records_flag_scan.py' -v
```

These commands passed on a native Linux x86-64 tree at the stated base with
the independent additive packets. The focused predecessor file passed all
17 tests; the three related files together passed 46. Raw focused
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
