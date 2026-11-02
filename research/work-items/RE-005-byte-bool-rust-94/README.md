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

The actual experiment ran successfully on clean source checkpoint
`56244f5c34c5ec0c2a7cab90a42d450ce757081b`, after independent source and guarded
runner review. `actual/COMMANDS.json` retains 45 actual experiment commands
and their 90 streams; the nested native ledger retains the GNU version and
two disassemblies. `actual/COMPRESSION.json` binds every lossless compressed
stream and physical-input audit to its original bytes/hash. No failed earlier
experiment was replaced: this is the first actual run of the new component.

| Actual comparison/check | Result |
| --- | --- |
| O0 library + separately linked input-only client | 5,628/5,628 complete canonical records identical |
| O3 library + separately linked input-only client | 5,628/5,628 complete canonical records identical |
| Source relational tests | 4/4 pass at each direct build |
| Real Cargo offline/locked debug and release | 4/4 integration tests pass in each profile; zero library/doctests |
| Clean repeat O3 library, same basename | Own raw rlib bytes identical |
| Native collector and static tests | Complete 197B/64 rows; 13 tests pass |
| Raw comparator controls | Altered content detected; missing and extra rows rejected |

All five independently compiled source mutations emit the full 5,628 normal
records and fail an actual relational assertion (exit 101):

| Deliberate source defect | Mismatching complete records |
| --- | ---: |
| Charge every nonzero mode | 2,592 / 5,628 |
| Roll back the retained counter on limit failure | 224 / 5,628 |
| Omit the boolean budget-error word write | 144 / 5,628 |
| Accept boolean byte 2 | 212 / 5,628 |
| Restore the input slice after invalid boolean | 1,850 / 5,628 |

The 13 static tests include ten copied-input byte/FDE/CIE/mapping/relocation
corruptions below the whole-target digest check, plus complete identity and
failure-preservation checks. These are structural rejection controls, not
execution of a mutated capture. `actual/ARTIFACTS.json` records digests of
the retained local build products; built executables and Cargo output remain
local under ignored `work/`.

Before/after audits are identical across **10,536 root physical files plus
305 files in seven genuine pinned views**, their modes/heads/status, all 103
official research-provider payloads and both installed component manifests,
the owned Cargo binary and selected host tools. The compiler is research
Rust 1.94.1 (`e408947bf`); Cargo is 1.89.0. Actual argv/environment records
bind explicit GCC/BFD selection, a fresh owned offline Cargo home, and clean
environment. This is own-source build repeatability and a proven normal-state
relation, not target machine-byte identity.

`static/` retains the subsequent repository checks on clean evidence
checkpoint `30f04afefa59d2203e0d3b55bd35f4ff2539ecf3`: `make doctor`,
`make verify`, `make catalogue-check`, and `make reproduce` all exit 0.
Their before/after audit is identical over 10,655 root plus 305 pinned-view
physical files (10,960 total), seven pins, 103 provider payloads and two
installed manifests. Elapsed check time is 38.294 seconds. The measured Rust
source at C1 is unchanged; this later packet adds retained results and reviews.

Original source names/types, result ABI/padding, physical pointer identity,
aliasing, concurrent mutation, faults, unwind and target compiler provenance
remain unknown or excluded. This does not establish the whole serialization
component, whole-node compatibility, or target machine-byte identity. Current
expanded test/evaluator suite and hosted CI are **NOT_RUN**; every component
completion gate remains false. Imported/reference rights and pinned revisions
are unchanged. The older outer-wrapper finding is occupied by PR #1365 and
is not included here.

Next question: which caller-selected field sequences reach these two leaves,
and what additional state invariants do those callers require?
