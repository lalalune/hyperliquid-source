# RE-004-pointer-sum-rust-94: Recover the full-width conditional pointer-sum value

- Component: foundation; bounded static reconstruction supporting RE-001/RE-002 and later arithmetic work. No quantity type or full RE-004 completion claim.
- Submission base: `966865f1637a29ce75b019e1bf11d5529cc6f519`; pre-Rust freeze base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The scope/accounting update changed no selected artifact or predecessor checker.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: ELF virtual addresses, no runtime rebasing.
- Authorship: new Rust independently derived from admitted bytes and static instruction reasoning. No can1357 implementation was read or copied.
- Claim: finite static-model/compiled-Rust value and access-event agreement. This packet's qualifier neither executes nor emulates captured code. All component gates remain false. This does not deliver a source-built network node, Docker image or current-network compatibility.

## Evidence and bounded question
The locked 29-byte FDE is `[0x521cc40, 0x521cc5d)`. Both zero tests use
64-bit RDI/RSI. There are no loads or outgoing calls. Full RAX is
`(a+b) mod 2^64` when either operand is zero, otherwise `(a+b-12) mod 2^64`.
The correction is 12, not a type-size inference. Inputs with zero low words
but nonzero high words take the nonzero path. The existing checker pins
three incoming call-site bytes and caller FDE records; this is not a complete
decoded xref census. No other register, flags or calling ABI is reconstructed.

Input columns are `a,b`; expected columns contain full RAX. Boundary crosses,
single bits, wraparound and deterministic random pairs are retained. The new
contribution is independent Rust for the already established static rule,
with full-word zero-test and wrapping controls; no new function discovery is
claimed. `pointer_sum` is an inferred label, not a recovered symbol.

Admission uses `tools/foundation_pointer_sum.py`, pinned by SHA-256 in
`preparation/ORACLE-FREEZE.json`, including their original FDE/CIE, neighboring
boundary, call-site and relocation controls. Those Python checkers' byte-pattern
scans do not establish every decoded instruction or indirect caller. For a
reproduction, use this exact base or unchanged checker identities. New body
controls compare complete selected windows; the range companion also checks
each RIP displacement. Re-flipping a boundary byte reaches the structural
validator independently of full-capture hashing. A separate wrong-capture
control exercises identity rejection. See retained `target-*.txt.gz` disassembly.

## Before Rust, implementation, and reproducibility

Before `src/node94-pointer-sum/lib.rs` existed, `contract.py` admitted the captured
image and froze inputs and expected observations. Its register-oriented
expression and separately written closed expression agreed for every frozen
row. The retained freeze records `new_rust_exists_at_freeze=false`, exact
contract/vector/checker hashes and the base. These two expressions share a
static interpretation and are **not independent native execution or formal
ISA proofs**. Freeze order is documented evidence, not a signed timestamp.
The original Windows JSON freeze bytes are retained losslessly as `preparation/ORACLE-FREEZE.original.json.gz`; `freeze-transport.json` binds the CRLF-to-LF transport normalization for Git. Its parsed record, contract and observations are unchanged. The freeze command deliberately refuses once the new library exists; normal
reviewers should run qualification, not regenerate preparation.

The implementation is a standalone safe `no_std` Rust library plus an actual
stdlib stdin client. There is no Cargo workspace, lockfile, external dependency,
runtime application stub or imported machine-code implementation. Callback
load primitives model address arithmetic and successful observed values.
They are not native pointer dereferences, fault delivery, speculation, flags,
atomicity or architecture memory-model emulation. Noncanonical/wrapping test
addresses are algebraic view controls, not executed process addresses.

On a normally prepared checkout (read setup and manifests first):

```sh
bash scripts/setup.sh
python3 research/work-items/RE-004-pointer-sum-rust-94/verify.py \
  --rustc "$HOME/.rustup/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin/rustc"
make doctor verify catalogue-check
make reproduce
make test
```

The qualifier uses Rust 1.94.1 / LLVM 21.1.8, edition 2021, O0 and O3,
overflow checks enabled, native Linux x86-64 host. It checks immutable
preparation identities, the entire corpus, source copy and target admission;
compiles and runs a unit test and a separate linked client at both levels;
then compiles three semantic mutants. Clients receive **ID and inputs only**,
never the expected-value column. Source-copy hashes, exact compiler commands,
exit codes, stdout/stderr, observed rows and emitted LLVM IR are retained in
`qualification/`. Only repository/home path prefixes are normalized in public
logs and IR. Values, comparisons and instruction operands are not masked.
LLVM definitions establish compiled function presence, not target byte identity.

## Results and controls

- 2,656 frozen rows; O0: 0/2,656 mismatches; O3: 0/2,656 mismatches.
- Two Rust unit-test invocations passed (one whole-corpus test at each level).
- Checked missing-view refusals: 0; these are included in the fixture denominator but are not successful native executions.
- 2 body-boundary byte corruptions and the wrong-capture control were rejected.
- `truncated-zero-test`: 220/2,656 differing observations; normal process exit.
- `wrong-correction`: 2,517/2,656 differing observations; normal process exit.
- `saturating-add`: 1,150/2,656 differing observations; normal process exit.

`qualification/result.json` gives the exact denominators and output/source
hashes. `repository-checks/` retains shared native-base checks with all five
independent additions present, explicitly **not five separate full-head
suite passes**. `make doctor verify catalogue-check` and `make reproduce`
passed. Six focused foundation test files passed (66 tests). The complete `make test`
inventory was attempted with a 60-second timeout; see `scope.json` and its
raw log on freeze base `56c0ec67`: exit 124, 7/971 files started and 6 files completed (178 reported tests); the seventh was interrupted. Existing suite checks include project instruction-analysis models; the packet qualifier itself only evaluates the frozen equations and new Rust. It did not establish a
whole-suite pass. After rebasing to `966865f1`, doctor/verify/catalogue-check/reproduce passed again and both changed test files passed all 67 tests; `rebased-scope.json` and logs retain this separately. The packet Rust qualification also passed again on the submission base. No complete suite on that base is claimed. No existing test/check was weakened. Initial test-client
compilation exposed missing std Vec imports under `no_std`; those imports
were fixed before the retained passing qualification.

## Remaining gaps and next step

Native raw-equal / relocation-normalized / unmatched compiled-window counts
are **not measured**. No opcode transplant, byte-equality, native ABI,
exception/fault, full-input-domain theorem, whole-function state equivalence,
whole-component or whole-node claim is made. Finite generated expectations
cannot replace a separately authorized native differential harness. Existing
imports, captured artifacts, submodule pins, progress and catalogues are
unchanged. The next question is to validate the caller's actual value/return
type and ABI using independently decoded call paths, then compare the Rust
under a separately authorized isolated target harness. No gate is requested.
