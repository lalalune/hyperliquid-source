# RE-004-byte-index-rust-94: Recover branch-dependent RSI and inclusive indexed-byte reads

- Component: foundation; bounded static reconstruction supporting RE-001/RE-002 and later arithmetic work. No quantity type or full RE-004 completion claim.
- Submission base: `966865f1637a29ce75b019e1bf11d5529cc6f519`; pre-Rust freeze base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The scope/accounting update changed no selected artifact or predecessor checker.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: ELF virtual addresses, no runtime rebasing.
- Authorship: new Rust independently derived from admitted bytes and static instruction reasoning. No can1357 implementation was read or copied.
- Claim: finite static-model/compiled-Rust value and access-event agreement. This packet's qualifier neither executes nor emulates captured code. All component gates remain false. This does not deliver a source-built network node, Docker image or current-network compatibility.

## Evidence and bounded question
The locked 22-byte FDE is `[0x556bfe0, 0x556bff6)`. First read one byte at
`base+1` into full RDX. Compare the count against **low32(RSI)** unsigned.
If index exceeds count, return RAX=0 and retain incoming **full RSI**.
Otherwise `mov esi,esi` clears its high word and a second byte is read at
`base+8*index+8`; return that byte in full RAX and the zero-extended index in
RSI. Equality takes the load path, even for count/index zero. No outgoing
call exists. The old checker pins one e8-pattern candidate and its caller
FDE, without a complete xref claim. Runtime object type/layout beyond these
accesses is unknown. New evidence extends the old RAX-only value rule with
branch-dependent full RSI and exact conditional read order.

Input is `base,incoming_rsi,count,entry_byte,entry_present`. Output is
`tag,RAX,RDX,RSI,read_count,read_addresses...`. Tag zero is a successful
synthetic view; tag one is a checked missing-byte refusal, with zero
placeholders rather than claimed native registers after a fault. The count
byte is always mapped. Missing entry bytes on the no-load path prove the
guard is lazy; one missing byte on the taken path is an error-model control.
All 256 counts crossed with indices 0..256 are present (65,792 pairs), plus
payload, high-RSI and address-wrap controls. This finite cross covers the
count/low-index boundary, not every 64-bit base/RSI/payload combination.

Admission uses `tools/foundation_byte_indexed_load.py`, pinned by SHA-256 in
`preparation/ORACLE-FREEZE.json`, including their original FDE/CIE, neighboring
boundary, call-site and relocation controls. Those Python checkers' byte-pattern
scans do not establish every decoded instruction or indirect caller. For a
reproduction, use this exact base or unchanged checker identities. New body
controls compare complete selected windows; the range companion also checks
each RIP displacement. Re-flipping a boundary byte reaches the structural
validator independently of full-capture hashing. A separate wrong-capture
control exercises identity rejection. See retained `target-*.txt.gz` disassembly.

## Before Rust, implementation, and reproducibility

Before `src/node94-byte-index/lib.rs` existed, `contract.py` admitted the captured
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
python3 research/work-items/RE-004-byte-index-rust-94/verify.py \
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

- 68,193 frozen rows; O0: 0/68,193 mismatches; O3: 0/68,193 mismatches.
- Two Rust unit-test invocations passed (one whole-corpus test at each level).
- Checked missing-view refusals: 1; these are included in the fixture denominator but are not successful native executions.
- 2 body-boundary byte corruptions and the wrong-capture control were rejected.
- `exclusive-count`: 1,057/68,193 differing observations; normal process exit.
- `unconditional-rsi-truncation`: 25,792/68,193 differing observations; normal process exit.
- `wrong-stride`: 33,152/68,193 differing observations; normal process exit.

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
