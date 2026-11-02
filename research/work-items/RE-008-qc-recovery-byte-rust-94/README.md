# RE-008: compiled QC-row one-byte field projection

This closes the compiled-reconstruction gap for the qualified field relation
already established by `RE-008-qc-recovery-byte-94` at commit
`6279dcfbd88655e08ed1632227f6840e1ade7a9e`. The captured node is never executed
or emulated. Expected values come from authenticated static evidence.

- Target: Linux x86-64 node94, SHA256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Native owner FDE: `[0x4c7e340,0x4c7e60d)`; field entry `0x4c7e4f3`.
- Real component: existing `src/node94-consensus-admission`, unchanged manifest,
  lockfile and dependencies. The isolated `qc_recovery_byte` module and input-only
  example fit its node94 QC scope without a new crate/workspace. Admission and
  authentication do not call this module.
- Scope: final charge, logical input consumption/suffix, byte result and the
  observed error kind/word. Prior raw20 and both four-word group successes are
  premises. This is a field projection, not a complete decoder or crypto result.

## Native relation and API boundary

The static packet proves mode1 overflow rejection before any charge store;
otherwise charge increments before the limit comparison. A limit error retains
that increment. Physical EOF follows charging and also retains any increment.
Permitted nonempty input consumes one byte without a value check. Other mode
values bypass charging; their reachability in a source decoder is unknown.

The Rust module independently expresses this with checked arithmetic and a
borrowed slice suffix. `ChargeState`, `FieldError` and their names are new safe
API choices. Both native errors store word1 at O+0x10; only EOF establishes its
shortfall meaning. No original Rust error enum, inactive output bytes, layout,
calling convention, raw pointer provenance or lifetime is recovered.

Input slices must be valid and live; state, input and native output satisfy the
static packet's disjointness/ordinary-return premises. The safe API excludes
dangling/inconsistent raw pointer-length states and follows host slice length
constraints. It compares logical pointer delta and remaining content, not
native instruction store order, trace, concurrency or allocation behavior.
The native charge/pointer/remaining/output ordering stays in the static proof.

## Independent expectations and actual Rust execution

`oracle.py` imports no Rust or packet implementation model. It authenticates the
12 pre-model CSV boundaries and frozen native windows by their existing hashes.
It separately constructs 2,560 all-byte cases: all256 values, lengths1/2, for
mode0, mode2, admitted mode1, limit-equality mode1 and overflow mode1. The second
byte is first XOR0xa5, exposing incorrect suffix/width behavior. Mode2 cases are
conditional field-entry states, not proven whole-decoder inputs.

The complete 2,572-row input stream is fixed to SHA256
`543593d9b4c23e919f95b5bd37e860e3eee783b814f4fa582285e8d3db1aac6c`;
the separate expected stream is fixed to
`90c44eb754ad03cec387b6da73353c1b57b66c666cc37bce17e87d592a2cc901`.
These pins predate the first Rust run. The twelve CSV expectations predate the
Rust draft; the all-byte relation was authored separately from its checked-add
control flow. No target execution supplied either stream.

The example receives only record id, mode, charge, limit and input bytes. It
prints actual status, charge, consumed count, remaining count/content, value and
observed error fields. Expected answers are compared in the Python parent after
the child exits. This is reviewed input/output data flow, not an OS sandbox.

`verify_rust.py` snapshots the existing real component's manifest, lockfile and
all compiler project sources before building. It preserves their hashes and
checks Cargo dep-info source closure, compiler/executable identity and fixture
identity. Fresh debug/release targets use offline locked Cargo, rustc1.94.1,
warnings denied and overflow checks enabled. It captures every command, exit,
stdout/stderr and actual output under the requested ignored output directory.

## Source controls and native controls

All six single-recipe source mutants must compile successfully, run with exit0,
and disagree with at least one qualified field-entry expectation in each profile.
Compile failure is not accepted as a semantic witness. These are source faults
with native-derived counterexamples, not exact mutant/native ABI comparisons.

| Source fault | Disagreeing rows per profile |
| --- | ---: |
| Discard charge on limit failure | 516 |
| Check EOF before charging | 3 |
| Admit old charge equal to limit | 515 |
| Weaken overflow rejection with wrapping addition | 513 |
| Consume two bytes when available | 769 |
| Reject byte values above1 | 1,528 |

The six native byte/CFG controls in the prior packet remain distinct: they
exercise authenticated branch/dataflow/width facts below identity admission.
The eleven comparator-only output corruptions in `oracle.py --self-check` are
comparison sensitivity controls; they are not Rust or target runs.

## Reproduce

Use an existing official pinned compiler; no tool installation is performed:

```sh
python3 -B research/work-items/RE-008-qc-recovery-byte-rust-94/verify_rust.py \
  --rustc /path/to/verified/rustc --out work/qc-field-rust-new
cargo test --offline --locked \
  --manifest-path src/node94-consensus-admission/Cargo.toml --all-targets
cargo test --offline --locked --release \
  --manifest-path src/node94-consensus-admission/Cargo.toml --all-targets
```

Actual receipts and focused/repository check outcomes are summarized in
`RESULTS.json`. Full repository `make test` is deferred to coordinator
integration. No hosted-CI, native execution/equivalence, complete QC decode,
prior-group closure, cryptographic validity, binary matching or full gate is
claimed. Gates and progress files remain unchanged.
