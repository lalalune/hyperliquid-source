# RE-001-count-scale-rust-94: scaled-count caller with post-call base reload

- Research allocation: foundation / RE-001, bounded semantics and independent Rust.
- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: ELF virtual addresses, not runtime addresses.
- Source: `src/node94-count-scale/lib.rs`; no external Rust dependencies or invented Cargo workspace.
- Status: finite static-observation/compiled-Rust agreement. Native ABI, target execution and byte equivalence are not claimed.

## Gap and observed sequence

The complete FDE is `[0x51c96d0,0x51c9701)`. Load a u32 count at
incoming RSI, then a qword base at RSI+8. The call to 0x51c4000 receives the
observed RDI/RSI/RDX/RCX projection `(base, base+80*count, incoming_RDX,
incoming_RDI)`, with u64 wrapping address arithmetic. After it returns, reload
the qword at the saved incoming RSI+8. Subtract that post-call value from RAX,
wrap to 64 bits, arithmetic-shift right by 4, multiply the low dword by
0xcccccccd, and retain the low 32-bit result.

The base static packet described scaling but no independently authored Rust
caller existed at this source path. This reconstruction preserves the explicit
call argument projection and the *post-call* read, without assuming that the
opaque helper cannot modify the field. The safe callback contract permits
that modification; it does not assert that the actual unresolved callee does
modify it. Tests exercise both unchanged and changed post-call bases, signed
and misaligned deltas, high u32 counts, wrapping pointers, 1,024 seeded cases,
and refusal of each reached operation. Trace comparison pins the actual call
and read order. The helper implementation and native ABI remain unresolved.

## Admission and independent comparison

Before Rust source existed, run the existing `foundation_count_scale.py` inspector against
the authenticated target and freeze its output, a Python observation contract
and the finite corpus. `ORACLE-FREEZE.json` binds all three digests and records
the absent Rust path. `verify.py` re-authenticates the exact target through that
unchanged base inspector and checks the frozen files and regenerated rows.
It does not bless an arbitrary digest or accept a comparator based only on
new Rust behavior. The retained inspector locks body bytes, unwind evidence,
padding and its bounded cross-reference observations. Read its limitations;
an incoming byte-pattern scan is not a complete xref census.

Compile the independently authored library and its separate stdin client with
rustc 1.94.1, edition2021, opt-level0 and opt-level3. Each optimization level
is built twice from identical source with a remapped repository path. Both
the client and rlib repeat byte-for-byte at the same level. Compare all
1,984 frozen observations on each of the four executions. Compressed
raw outputs and exact source/build hashes are in `qualification/`. No original
node code is executed, transplanted, instruction-emulated or used as a linked
library. The unlicensed inferred reference is not copied.

Normal-exit corruption controls verify that the comparator detects:

- `stale-precall-base`: 1,359/1,984 observations differ; normal process exit.
- `wrong-stride`: 1,407/1,984 observations differ; normal process exit.
- `wrong-magic`: 1,010/1,984 observations differ; normal process exit.

These are finite tests, not a proof over every u64 state. Safe view errors
propagate without invented native fault recovery. Object meanings, source
ownership, native layouts/ABI, stack/unwind execution, callee closure where
present, synchronization, full indirect xrefs and whole-ELF identity remain
unestablished. No component gate, matched-byte count or ownership denominator
is changed. No live networking, chain actions, private data or captured
binary execution is part of qualification.

## Reproduce

On Linux x86-64, with pinned inputs prepared through `bash scripts/setup.sh`:

```sh
python3 -O research/work-items/RE-001-count-scale-rust-94/verify.py --rustc /path/to/rustc-1.94.1
rustfmt --edition 2021 --check src/node94-count-scale/lib.rs src/node94-count-scale/client.rs
make doctor verify catalogue-check
make reproduce
make test
```

The first two commands are this bounded Rust check. Repository checks are
recorded separately below; never infer a whole-suite pass from them.

## Repository checks and limits

`make doctor verify catalogue-check` and `make reproduce` passed on the exact
base with independent source/evidence additions in one shared native
validation tree. Imported files and pins remain unchanged. No whole-node
build exists. Full `make test` started 51 of 971 files: 50 completed with
866 reported tests and one skip; the 51st was interrupted when the operator
selected drafts with completed focused validation. No completed file failed.
This is not a complete sweep or a whole-suite pass on any separate PR head.

Next step: review the explicit projection and data/callee/ownership gaps before
using this partial safe-view reconstruction in a native implementation.
