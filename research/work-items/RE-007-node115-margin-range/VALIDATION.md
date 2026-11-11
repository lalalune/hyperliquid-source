# Actual validation and limits

Host execution used macOS arm64, Rust/Cargo 1.95.0 and Python 3.14.3.
Static exports used GNU binutils 2.47.20260726. The authenticated capture was
only read as data. No captured instructions, node or visor were executed,
emulated or evaluated.

## Authorship and qualification order

The reference author first specified the conditional host contract and a
linear traversal. Independent review found that the manual controls checked
the selected projection but not the complete returned slices. Literal
physical-index lists were added before either actual generator run. The
reviewer's final read of that amendment followed those runs; it is not
described as a final pre-execution review gate.

Both actual generator runs exited zero and produced four byte-identical
files. The frozen corpus contains **7,635 records**: twelve manual cases,
7,063 exhaustive small-domain cases, 512 seeded cases and 48 additional host
rejections. Exhaustiveness is limited to capacities 0 through 6, every head
and live length, nondecreasing keys from {0,1,3}, and seven declared queries.
The manual and seeded cases additionally exercise full-u64 boundaries,
inactive bytes, duplicated keys across the seam and zero divisor bytes.

Reference inputs and expectations were frozen before Rust authoring. The
source author read the host contract and native interpretation, but did not
read the reference implementation or expected corpus before the source
freeze. This is separate authorship and algorithmic comparison, not an
independent native evidence lineage. A name-only amendment changed the binary
from `margin-range-driver` to `margin-range`; library, driver logic and lock
did not change. Both source freeze records and the amendment are retained in
[source-authoring](validation/source-authoring/).

The parent read all five final source files before compilation. Independent
source review also found no actionable defect, but its final receipt was
sealed three seconds after the qualification completed. It is peer review,
not a claimed pre-execution final gate.

## Actual public reproducer run

The packet's `reproduce.py` was actually run, using an explicit installed
Cargo path and a fresh output directory outside the repository. It ran
**40 child commands**. [RESULTS.json](validation/run-01/RESULTS.json) records
commands, exit codes, stream hashes, binary hashes and comparisons;
[ARCHIVE.json](validation/run-01/ARCHIVE.json) describes the retained streams.

- Debug, release and a repeated release each exited normally with empty
  stderr and **7,635/7,635 exact expected rows**. The two release binaries
  have SHA-256 `5090636e83b38f9b48d5835ab94c0360f31214384b7e00cd594eaef87b97fad3`.
- Eight independently compiled semantic variants all built successfully and
  returned complete, syntactically valid 7,635-row output streams. Their
  mismatch counts were **2,269; 5,713; 4,103; 294; 838; 6,809; 2,180; 3,107**
  for M01 through M08. A compile failure, crash or malformed response is
  rejected as qualification failure, not counted as semantic detection.
- The actual production comparator accepted the valid stream, rejected seven
  malformed/corrupted streams and counted exactly one changed value in a
  syntactically valid stream. An independent pre-execution helper review also
  exercised eighteen synthetic controls against its pure parser/comparator.
- Fourteen malformed-input cases plus an extra-argument case returned exit 2
  with empty stdout. Empty input returned zero with empty streams. These are
  selected transport controls, not complete I/O, allocation or resource-limit
  qualification. The 50,000-record ceiling and actual I/O-failure behavior
  were source-reviewed but not separately exercised by this run.

The source mutations are retained in
[MUTATIONS.json](validation/MUTATIONS.json). M08 drops the wrapped second span
and adjusts its reported count so the output remains parseable. Test failures
therefore reflect the wrong returned range, rather than malformed transport.

Before execution, helper review found that its initial comparator normalized
CRLF and accepted malformed numeric output, that its comparator controls did
not call the production comparator, and that path confinement and partial
failure recording needed tightening. These were corrected before the actual
run. A second review found no remaining blocking helper issue. Source,
expectations and their frozen hashes were not changed to obtain passing
qualification.

The archive retains all **80 stdout/stderr streams** in the deterministic
`validation/run-01/streams.tar.gz` container. Stream filenames in RESULTS and
ARCHIVE name its members; each member is an individual gzip stream. All
eighty members were checked byte-for-byte after assembly. Sixty-nine are byte
exact. Eleven build diagnostic streams have only declared local output/tool
path prefixes projected. All driver output bytes remain exact. Stored and
original hashes are separate. No binary, build directory, credential or
personal runtime state is included. Other copied metadata projections are
listed in [PATH-PROJECTIONS.json](validation/PATH-PROJECTIONS.json).

## Static and repository checks

The public static verifier exited zero for the full authenticated target,
binding both complete bodies, their FDE/CIE records, complete exported bytes,
the selected direct call and the diagnostic relocation. A wrong target file
and modified export were rejected by the outer hash checks, both exit 1
before creating output. These are authenticity controls, not semantic
instruction mutation coverage. See [static records](validation/static/).

A separate offline locked `--release --lib --target x86_64-unknown-linux-gnu`
build passed. The library SHA-256 is
`5b07fb43c600b32c423a5a9e9c32bcee1bdf384431fe598374269213a2a3f918`.
It was **built, not executed**; no Linux driver/runtime or hosted CI result
is claimed. See [its receipt](validation/linux-library/RESULT.json).

Base `make doctor` and `make verify` passed, including 32 imported files,
all six pinned source repositories, and 558 manifests / 7,154 packet entries.
The initial base `make catalogue-check` failed because README was stale.
That original failure is retained. Registering this risk implementation and
running `make catalogue` regenerated the tables; `make catalogue-check`,
`make reproduce` and Rust formatting then passed. Generated work-item totals
also account for the base's existing directory-count drift.

Final packet and staged checks are recorded separately. Broad `make test`
and hosted CI were not run: the broad suite includes captured-instruction
evaluators outside this static-only task. The submission uses `[skip ci]`.
All 92 full-component acceptance gates remain false. Finite comparisons
against the conditional static contract do not establish target-runtime or
whole-node equivalence.
