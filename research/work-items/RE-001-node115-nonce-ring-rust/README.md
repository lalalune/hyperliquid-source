# RE-001: recover the node115 conditional nonce-ring invariant in Rust

> Current #115 migration (2026-11-02): this implementation was rebuilt and
> compared at opt-level 0 and 3 after retiring the older node and trimming
> its shared tooling. `migration-validation.json` records the fresh run and
> compiled mutation controls. Historical blocker reports below describe the
> original environment; they do not require the retired binary. Original
> negative results and target-bound records remain unchanged.


Component: l1 nonce-container foundation. This adds a genuine dependency-free
Rust component for the conditional adjacent-u64 ordering invariant. The earlier
[native five-body packet](../RE-001-node115-nonce-ordering/README.md) explicitly
leaves Rust recovery open. Its FDE/body/data binding is reused with credit;
those 1,685 native bytes and 480 instructions are not recounted as new mapping.

Target node115: artifacts/node/115/hl-node, 105896032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Prepared from base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
No unlicensed reference source is used. New source/docs MIT; captures retain rights.

Related open PR1396 traces the text provider and caller; that distinct work
is excluded here. This component recovers only the prior conditional
ordering predicate, not its provider or caller.

## Established contract and implementation

The observed native unsigned JB comparisons require every logical neighboring
u64 pair to increase strictly, across both contiguous spans and their wrap
boundary. Empty/singleton contents need no pair comparison. The source implements
this established relation directly with one logical ring walk, rather than
copying captured code or pretending to reconstruct the opaque input providers.

The source's unsafe C interface is an explicit logical comparison boundary,
not the original Rust ABI. It requires count <= capacity, a valid head (or both
head/capacity zero), capacity <= isize::MAX/8, and initialized nonwrapping storage.
The harness validates these synthetic-input preconditions before interpreting
own code. Neither it nor the source establishes malformed-metadata rejection
by original providers. Panic/error propagation, output metadata stores, ownership,
allocation, live nonce/replay policy and caller reachability remain unclosed.

## Measured evidence and controls

Actual offline locked Cargo release library build: Rust1.94.1/LLVM21.1.8,
Linux x86-64 target, Windows host. No root workspace is introduced.
The own compiled predicate is47 bytes/17 instructions. Two repeated own object
builds are byte-equal. No target byte-equivalence percentage is claimed.

The public compiler/comparator records14,161 exhaustive evaluations for arrays
of length0..4 over five unsigned boundary values, every valid head/count;
and47,872 additional evaluations for every valid head/count at capacities1..32,
with increasing, duplicate, decreasing and specified LCG-generated contents.
Both sets have zero mismatch. Another5,784 actual comparisons vary every
byte alignment0..7 for capacities0..8 and every valid head/count over three
logical patterns. The source uses read_unaligned to match x86-64 loads;
ordinary typed dereferencing would impose an extra Rust alignment premise. Counts are evaluations, not a claim of distinct
inputs across sets. Native expectations come from the original verified branch
operands and independent two-span pair obligations in the existing checker.

Three real source corruptions are compiled and rejected on retained native-based
counterexamples: accepting equals, skipping the wrap comparison, and omitting
the first comparison. Missing synthetic memory is independently rejected.
Only freshly compiled own Rust instructions enter the evaluator; the original
capture is static input and is rejected by the own-object entry point. There
are no new shared evaluator changes or ISA extensions. The minimal component
comparator closes a gap the existing native-only checker cannot validate.

Source/compiler/checker/native-spec/evaluator identities, original body/FDE
records, compiler flags, exact counts and controls are in rust-validation.json.
The own disassembly uses function-relative offsets, not original ELF VAs.

[PROOF.md](PROOF.md) separately derives the two-span/one-walk relation and
checks the retained own-object loop over the stated valid-storage domain.
It is a manual argument, not a machine-checked compiler proof.

## Reproduce

See src/node115-nonce-ring/README.md for Cargo and comparator commands.
The six focused methods cover target identity, native wrap/unsigned behavior,
invalid synthetic domains, object/capture rejection, retained provenance and
an actual compiler run. Without explicit HYPERLIQUID_NONCE_RING_RUSTC or
Capstone5.0.6 the compiler method skips honestly, never a Rust pass.

The compiler path is screened before even probing its version: captured artifact
paths/identities reject without dispatch. A subprocess spy protects this negative
boundary; the separate actual compiler method still performs genuine builds.

## Repository checks and limits

The exact source branch at base 56c0ec672bd8fdcfaa80f2db700a61e6240b3663 was checked on Windows/Python3.12.14. Before:971 isolated files,15162 tests. After:972 files,15168 tests. Both have121 failing files,83 failures,188 errors,284 skips; FAIL/ERROR header multisets are identical. All six new focused and full-run methods pass; focused elapsed9.237s. Actual installed offline locked Cargo Linux-target library build passed.

The changed-tree full inventory was interrupted by the operator. The first872 completed file runs were preserved, the interrupted873rd file was restarted, and all remaining100 files were run with the same fresh-interpreter unittest-discover command. Source/test hashes were checked unchanged across resumption. No partial file result was reused. This is a complete resumed inventory, not a single uninterrupted runner invocation. Logs and resumption provenance are retained locally. Doctor, artifact verification, imports, catalogue and reproduction checks each exited1; missing native/signature prerequisites and stale catalogue remain failures. No full-suite pass or hosted CI is claimed.

## Upstream integration validation

Latest reviewed upstream 966865f1637a29ce75b019e1bf11d5529cc6f519: candidate files and recursive local Python dependencies are unchanged from the tested base. Reviewed policy changes add dependency accounting and source-built-node delivery priorities; this bounded predicate advances no completion gate. The later integration tree and its additional tests have not received a full run. No captured executable or network node was executed.

No native Rust test executable, captured executable, network/node service,
private data, signature success, hosted CI, complete original ABI or node
completion gate is asserted. Next: recover the actual provider and normal/error
output contracts before wiring this predicate into a reconstructed nonce container.

Final diff hygiene removed one extra blank line at the checker EOF after the resumed inventory. No Rust or Python statements changed. Compiler provenance was regenerated from actual builds; all six focused tests then passed in5.812s. The full inventory above predates this whitespace-only edit.
