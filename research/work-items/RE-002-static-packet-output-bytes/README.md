# RE-002: preserve static packet bytes across host text conventions

- Component: analysis/build-provenance tooling; one output-formatting defect
  shared by six existing static analyzers, addressed together in this PR.
- Source baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Reference: `999556f6e0a474b8312db96ec3149e1c44e97c23`; no reference code used.
- Status: reproduced host I/O defect. No analysis semantics or progress gate changed.

## Reproduce

CPython 3.12.14 on Windows. From the repository root, choose a fresh output
directory; the proof refuses to overwrite earlier results:

```sh
python research/work-items/RE-002-static-packet-output-bytes/verify_cli_bytes.py --root . --out work/packet-bytes-proof
python -m unittest discover -s tests -v
```

The proof starts the six real analyzer CLIs against the unchanged capture and
compares their output bytes to existing committed packets. It explicitly sets
`PYTHONUTF8=0`, `PYTHONIOENCODING=cp949`, and records hashes of all six tool sources.
It checks 14 files plus both bincode JSON stdout streams, 16 comparisons total.
No mocks replace the analyzer, output file or target bytes. Only Python static
analysis runs; the captured node is never executed.

## Observation and fix

Default `Path.write_text` and text stdout apply host newline translation. On
Windows, explicit LF strings become CRLF bytes. The packet content parses as
the same JSON/TSV, but exact hashes and existing byte comparisons fail.

`before.json`: **0/16** byte-identical outputs. Replacing CRLF with LF solely
for diagnosis makes **16/16** equal to the existing fixtures, establishing the
shared newline cause. Raw generated baseline files remain in the ignored work
directory; no baseline fixture was edited or re-hashed to accept the defect.

`after.json`: **16/16** outputs equal the same fixtures without normalization,
with zero CRLF occurrences. File writes explicitly use UTF-8/LF; the two JSON
stdout streams write UTF-8 bytes directly. Renderers, field ordering, final
newline choices, decoded instructions and all target predicates are unchanged.
The proof records the original and corrected source/output SHA-256 values.

Affected tools are `bincode_varint`, `bincode_varint_decode`,
`evm_extra_wei_decimals`, `qty_newtype_sign_guards`, `spot_token_decimals`, and
`weipriv_sign_guard`. The other open output-format PRs address heartbeat,
catalogue and provenance, which are outside this change.

## Validation

The six existing real-target regression methods that failed on the preceding
baseline now pass, including both fixed stdout hashes and all four packet
regeneration comparisons. No tests, expected fixture bytes, golden hashes or
skip conditions were changed. No extra tests that merely mirror a write call
were added; the actual CLI comparison supplies additional file/stdout coverage.

Make is unavailable, so the required Makefile Python commands were invoked
directly with Git on PATH and a workspace temporary directory:

- Full suite: **357 tests in 108.648 seconds; 1 failure, 16 errors, 21 skips**.
  The remaining failure is a POSIX-only path assertion in the REA launcher test;
  errors include missing binutils and temporary-directory cleanup limitations.
  The full suite is not passing. The six output failures are resolved.
- Doctor completes with `analysis_ready=false` and missing native tools.
- Artifact verification passes all eight size/SHA-256 checks, then fails because
  GPG is unavailable; signatures are not reported as verified.
- Imports verification rejects the Windows reference checkout; reserved
  `node/aux.rs` cannot be materialized, and hydrated LFS inputs remain unstaged.
- Catalogue check fails on native backslash paths, covered by an existing PR.
- Reproduce is attempted and stops at artifact signature verification. Imported
  inventories, literal classifications and packet contents were not rewritten.

Target-equivalence/denominator changes, Rust implementation, code addresses,
normalization masks for comparisons, hosted CI and Linux/macOS runs are not
claimed. The only normalization above diagnoses the original host I/O error;
the successful comparisons use raw bytes. Original imports/pins are preserved.
Next question: run the same CLI byte comparison and required checks in the
fully provisioned Linux environment, without changing golden packet hashes.
