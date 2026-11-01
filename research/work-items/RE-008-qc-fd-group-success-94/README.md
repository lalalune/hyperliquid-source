# RE-008: second QC group's qualified four-word success path

## Gap closed

On node94, the second QC-row call at `0x4c7e422` invokes the group reader
`0x466bf60..0x466c13f`. For mode dword 1, admitted charge `C+32`, and four
consecutive `FD` plus eight-byte payloads, the group consumes **36 wire bytes**,
retains **charge `C+32`**, and writes **40 result bytes**: a zero tag qword and
the four little-endian value qwords in order. Arbitrary trailing bytes remain
unread. The group charges the decoded width, independently of these encodings'
length. No minimal-encoding test is present on the selected FD arms.

This closes the group-value/charge composition left opaque by draft
[#1509](https://github.com/lalalune/hyperliquid-source/pull/1509). It does not
extend that PR's recovery-byte or successful row-assembly claims. The primitive
u64 wrapper is prior work in
[#1365](https://github.com/lalalune/hyperliquid-source/pull/1365), head
`4d33431de9eb9c5c9c8d145d1e61b75a9634d57f`. Its proof covers scalar wrapper
state and a different request caller; this packet adds only the four-success
composition. The separate first-scalar failure lane is outside this claim.

## Bound evidence and implementation

- Target: node94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates are linked ELF virtual addresses; all ends are exclusive.
- `PRE-RUST-FREEZE.json` pins three complete native bodies/FDEs, eight input and
  expected rows, the four-entry wrapper jump table, and six operative byte edits.
  Freeze SHA-256:
  `5bece039bc93d4766db761711d189aa445874862845868e3b383ccdc98f1a4fc`.
- `native.gnu.txt` and `native.llvm.txt` export the complete 479-byte group and
  229-byte wrapper, plus the indispensable 60-byte second-call window. Their
  130/69/13 instruction partitions agree. The complete 717-byte row is hashed
  and FDE-bound without duplicating #1509's whole native export.
- `PROOF.md` separates the native argument from API choices and unknowns.
- Independently authored Rust is in the existing real component's
  `src/node94-consensus-admission/src/qc_fd_group.rs`; its existing manifest and
  lockfile are unchanged. This separate pure module belongs with the component's
  QC research; it is not connected to admission or authentication.

The safe API takes charge, limit, immutable input and an explicit 40-byte result
view. It checks the qualified domain before producing final state. `false` with
unchanged arguments outside that domain is a **chosen API behavior**, not a
native error contract. Successful final values, suffix and charge are compared;
the original ABI, pointer ownership, intermediate store timing and call trace
are not reproduced. Native charge-write order is separately documented.

## Validation

`RESULTS.json` retains exact tool/source/fixture identities, commands, stream and
executable hashes, counts and repository-check outcomes. Raw local receipts are
under ignored `work/qc-fd-group/`; both verifiers regenerate their own receipts.

- Fresh target authentication and FDE/body checks; two identical GNU/LLVM
  regenerations; eight frozen native-derived cases; six static semantic controls.
- Pinned Rust 1.94.1 compiles/runs the input-only example at opt0/opt3: 8/8 cases
  each. An independent Python reader decodes all 40 output bytes into five
  qwords, charge and suffix. Expectations never enter the Rust driver.
- All six compiled source mutants run successfully and disagree in both
  profiles. Counts are 7,8,8,8,8,7 of eight, matching the native operand controls.
  They change word reconstruction, qword destinations/source, or retained charge;
  none is killed only by a safe-API rejection or compiler failure.
- Existing component tests and focused static tests are reported in RESULTS.
  Full repository `make test` remains deferred to coordinator integration.

The eight rows were frozen before Rust existed: asymmetric full-width values,
zero encoded nonminimally as FD, exact limits, `C=MAX-32`, prefilled results and
unconsumed suffix canaries. They corroborate the static argument; they are not
eight executed target samples or an exhaustive runtime comparison.

## Reproduce

From the repository root, with authenticated node94 and installed native tools:

```sh
python3 research/work-items/RE-008-qc-fd-group-success-94/verify.py \
  --target artifacts/node/94/hl-node --llvm /path/to/llvm-objdump \
  --out work/qc-fd-group/static.json
python3 research/work-items/RE-008-qc-fd-group-success-94/verify_rust.py \
  --rustc /path/to/rust-1.94.1/bin/rustc \
  --out work/qc-fd-group/new-comparison
python3 -m unittest tests.test_qc_fd_group_success94 -v
cargo test --offline --locked --all-targets \
  --manifest-path src/node94-consensus-admission/Cargo.toml
cargo test --offline --locked --all-targets --release \
  --manifest-path src/node94-consensus-admission/Cargo.toml
```

Use a fresh comparison directory. `verify_rust.py` snapshots all component
`src/*.rs` plus only the selected example, retaining manifest/lock pins. Cargo
dep-info must match every compiler-read project input exactly, so an unrelated
example or an included expected-data file cannot silently join that closure.
No downloaded dependency or replacement workspace is introduced.

## Limits

Captured node/visor code was never executed or emulated. Expectations derive
from authenticated instructions and a mathematical projection. Other markers,
short inputs, reserve/primitive failures, panic/unwind paths and other modes
remain outside this claim. Caller-reachable mode construction, full QC decode,
signature validity, original compiler/layout/ABI, and runtime equivalence are
unresolved. The recovery-byte continuation may need one additional charge unit:
group success with `L=C+32` does not imply the whole row succeeds. All full
component gates remain false; no generated progress or catalogue is changed.
