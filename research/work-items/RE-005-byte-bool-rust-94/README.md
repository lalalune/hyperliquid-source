# RE-005: complete unsigned-byte and boolean decoder leaves

This packet supports independently authored safe Rust for two complete node
#94 leaves: unsigned byte `0x466bbb0..0x466bc09` (89 bytes/28 instruction rows)
and boolean `0x466be00..0x466be6c` (108 bytes/36 rows), totaling **197 bytes/64
rows**. Task-start base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Target `artifacts/node/94/hl-node` is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

The recovered relation includes literal-mode-1 charging, overflow before the
counter store, retained increment on limit failure, charging before empty
input, all 256 unsigned-byte values, and invalid boolean consumption before
error. The boolean budget-error path additionally writes word 1 at output
offset 8; the unsigned-byte budget error leaves that word unwritten. Safe Rust
records optional writes without reading or asserting native inactive bytes.

`NATIVE-INTAKE.json`, the two exact raw bodies/listings, and `PROOF.md` retain
complete FDE/CIE and normal-return branch evidence. There are no callees,
tables or RIP-relative data dependencies. The separately timed native image
closure supplement establishes executable mappings and no overlapping writes
among 80,300 actual RELA records. Its retained type-name typo is corrected by
`BYTE-NATIVE-IMAGE-CLOSURE-ERRATUM.json`: numeric type 18 is TPOFF64 (type 17 is
DTPOFF64); the numeric type and 8-byte interval checks are unchanged.

`FREEZE.json` seals **5,628 distinct inputs** and exact output records before
the new Rust was authored. `authority.json.zlib` losslessly retains the larger
authority document; `AUTHORITY-COMPRESSION.json` binds both representations.
The source peer reviewed the native/domain proof and complete new library,
input-only client, four relational tests, manifest/lock and component README.
The expected file is never supplied to the Rust library or client.

The scoped command, after a clean source checkpoint, is:

```sh
python3 research/work-items/RE-005-byte-bool-rust-94/run.py --out work/byte-bool-197-run1
```

At this source checkpoint the experiment has **not run**. The runner retains
each actual command and streams before checking its exit status; it compares
complete canonical JSONL at O0/O3, runs the real dependency-free Cargo tests,
and exercises compiled semantic controls. `collect.py` and `test_static.py`
authenticate complete native intervals and reject copied-input corruption;
they never execute captured instructions. Actual results will be recorded
separately after the run, including failures if any.

Original source names/types, result ABI/padding, physical pointer identity,
aliasing, concurrent mutation, faults, unwind and target compiler provenance
remain unknown or excluded. This does not establish the whole serialization
component, whole-node compatibility, or target machine-byte identity. Current
expanded test/evaluator suite and hosted CI are **NOT_RUN**; every component
completion gate remains false. Imported/reference rights and pinned revisions
are unchanged. The older outer-wrapper finding is occupied by PR #1365 and
is not included here.
