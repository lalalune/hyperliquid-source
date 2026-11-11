# Validation record

The baseline is `05bc2de303c05525b71e7e257426e741bc66a390`. It contains neither
this component nor this packet. This contribution adds a bounded reconstruction;
absence of code is not a reproduced production defect. The repository's
RE-004 task explicitly requests independently authored arithmetic and
target-grounded boundary tests. The allocation is `fees`, with no completed gate.

## Evidence order and identities

1. Static inspection of the complete point kernel, adapter and overflow hook
   produced the conditional numerical contract. Two independent readings
   agreed on the operation order and explicit FP/hook premises. The complete
   bodies, data, unwind records and relocations remain in `static/`.
2. The exact-rational reference was written without Rust. Its 62 author
   primitive cases and separately frozen 36 point / 26 primitive handcases
   all matched. This reference computes with mathematical integers/Fractions;
   it does not decode or evaluate captured instructions. Handwritten
   intermediate traces were not all checked by the comparison driver.
3. Two generator executions produced identical seven-file corpus trees:
   6,115 requested inputs, 215 duplicate aliases, 5,900 retained rows. Original
   independent expectations were preserved. Other expectations are explicitly
   reference-derived, rather than native outputs. Input-only TSV and expected
   TSV are separate, and the corpus was frozen before Rust authoring.
4. The Rust author used the static contract and did not read the mathematical
   reference implementation. The dependency-free package and input-only driver
   received complete source review before their execution. Actual offline,
   locked Cargo metadata validated the authored one-package lockfile.
5. Both host build profiles matched all 5,900 expectations. Two release builds
   produced identical binaries. A Linux x86-64 library build also succeeded;
   Linux code was not executed. Ten deliberately changed source variants then
   built and produced valid, complete output in both profiles, with the
   specified semantic differences. The comparator exits 1 for these intended
   mismatches; each Rust child exits 0. Process/format failures are not controls.
6. Twenty-six transport checks passed, including all 5,900 cases with new IDs,
   the 8,192-record boundary and 24 invalid-input refusals. These test chosen
   host policy, not a recovered native parser or ABI.

The reference SHA-256 is
`0ff857a3dd0e972bde5a361d3959b5706ca7c28485792b0550ad35d2af4a46d2`.
The corpus manifest SHA-256 is
`c54df191f0f8b83e6816d6cc31b78e0a61c601c333f096fe7eb34bc8a4bd586b`.
The pre-Rust freeze receipt SHA-256 is
`5d1c27259da41642813e22e8128ae137659eb28f5107206b33e0d8f23a530d99`.
The tested library and driver hashes are respectively
`419fcbbb778b34b3b2b9fcc9ff69846eaeb02fc8b66feb188bc5e1ea28481ff4` and
`5f98a3100bb8ab1c5385279c64d608cd439c5f1cecc88cd780052e2ab0bae9a8`.
Result prose added later does not alter those executable sources.

## Actual records and reproduction

[RESULTS.json](validation/RESULTS.json) contains the numerical counts, exact
build/output identities and every compiled mutation's named witness.
[logs.json.gz](validation/logs.json.gz) retains command records and stdout/stderr
with each original hash, projected hash, length and replacement count. Only
declared absolute path prefixes are replaced by `<REPO>`, `<FEE_RESEARCH>`,
`<SESSION>`, `<CAMPAIGN>` or `<RUST_TOOLCHAIN>`; original streams are retained
privately. Numerical results are not normalized. The public archive is a
portable projection, not a claim that its text bytes equal every original stream.

The public reference outputs are also retained verbatim in
`validation/reference/`. All seven frozen corpus files are byte-exact copies.
`fixtures/ADDENDUM-PROOF.md` separately proves the exact-`2^64` carry witness
without rewriting the original 36-case freeze or changing the generated row's
reference-derived provenance. The temporary, unexecuted generator addendum
draft was preserved privately and the original generator restored; neither
corpus run used that draft. The freeze pins the original generator.

The first static attempt failed on a metadata address error before completing
controls or invoking a decoder. The initial wrong anchor and raw failure were
preserved; a separate amendment corrected CMOVA to `0x3876684`. The successful
normal/optimized runs each exercised 56 controls, and two complete GNU
collections were identical. Public script docstring edits were rechecked:
all 56 controls passed again, with unchanged semantic observations.

Source review also caught the comparator's original use of Python's broad
`splitlines()`. It was corrected to literal LF splitting before any compiled
Rust comparison. An actual parser-only check showed that five non-LF ASCII
separators admitted by the original parser were refused by the corrected one;
the valid LF control passed. No expected output was changed to obtain a pass.

Use the exact commands in [README.md](README.md). The reference checks can be
repeated separately, without reading the captured artifact:

```sh
python3 -B -S "$fee_packet/oracle/qualify_primitives.py" \
  "$fee_packet/oracle/primitive_cases.json"
python3 -B -S "$fee_packet/oracle/qualify_independent.py" \
  "$fee_packet/fixtures/candidate-cases.json" \
  "$fee_packet/fixtures/primitive-boundaries.json"
python3 -B -S "$fee_packet/oracle/generate_corpus.py" \
  --handcases "$fee_packet/fixtures/candidate-cases.json" \
  --output "$fee_work/regenerated-corpus"
```

The recorded host is macOS/aarch64 with installed Rust 1.95.0, Python 3.14.3
and GNU binutils 2.47.20260726. Actual compiler/linker versions, argv,
environment and stream identities are in the command archive. Host corpus
agreement does not establish native x86-64 execution or byte identity. No
compiled-code window or whole-component acceptance gate is requested.

Full `make test` and hosted CI are not claimed. The broad current suite
contains captured-instruction evaluators, beyond this static-only workflow.
Whole-helper traversal, diagnostics, returned winner/state, effects, units,
FP initialization, hook completion and full-node equivalence remain open.
