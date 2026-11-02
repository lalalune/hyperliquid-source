# RE-001-pair-load-rust-94: ordered pair read from one full-width pointer

- Research allocation: foundation / RE-001, bounded semantics and independent Rust.
- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: ELF virtual addresses, not runtime addresses.
- Source: `src/node94-pair-load/lib.rs`; no external Rust dependencies or invented Cargo workspace.
- Status: finite static-observation/compiled-Rust agreement. Native ABI, target execution and byte equivalence are not claimed.

## Gap and observed sequence

The complete FDE is `[0x502b460,0x502b477)`. Load a qword pointer
from incoming RDI+0x28, then read RDX from pointer+0x198, followed by RAX
from pointer+0x190. Both field reads use the original pointer; the second is
not a dereference of the first result. The Rust API returns the full pair
after those three reached reads. No writes or outgoing calls are introduced.

The dictionary-backed Python oracle and the independently written Rust
BTreeMap client initialize actual little-endian bytes in a stated order:
object pointer slot, high/RDX field, low/RAX field, then remove spans selected
by three mask bits. Thus overlaps affect the pointer actually loaded rather
than silently assuming disjoint memory. Cases include exact pointer/field
aliases, high-bit values, wrapping addresses, every span-removal mask and
512 seeded fixtures. Compare the result plus reached-read addresses/order.
Safe missing-byte refusals are not claimed to reconstruct native faults or
partial register state on faults. The original static packet corrected a
scout's mistaken chaining account; this adds the independent Rust memory-view
reconstruction, not a new source-type or consumer interpretation.

## Admission and independent comparison

Before Rust source existed, run the existing `foundation_pair_load.py` inspector against
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
896 frozen observations on each of the four executions. Compressed
raw outputs and exact source/build hashes are in `qualification/`. No original
node code is executed, transplanted, instruction-emulated or used as a linked
library. The unlicensed inferred reference is not copied.

Normal-exit corruption controls verify that the comparator detects:

- `truncate-pointer`: 361/896 observations differ; normal process exit.
- `chain-second-read`: 210/896 observations differ; normal process exit.
- `wrong-first-offset`: 421/896 observations differ; normal process exit.

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
python3 -O research/work-items/RE-001-pair-load-rust-94/verify.py --rustc /path/to/rustc-1.94.1
rustfmt --edition 2021 --check src/node94-pair-load/lib.rs src/node94-pair-load/client.rs
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
