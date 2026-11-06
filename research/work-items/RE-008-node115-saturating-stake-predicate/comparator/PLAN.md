# Parent-side stake result comparator: unexecuted source proposal

This bounded validation tool belongs to the proposed node115 stake predicate.
It is not reconstructed Rust, a reference implementation, a semantic corpus,
or a generic test framework. Both Python sources are drafts for parent review;
neither has been imported or run by the author.

Host contract: `4bb6a164423609b2310b7952351be5e88f8583d205b1ec144e9393cfde92a28e`.

## Files and effects

- `compare_results.py`: standard-library-only pure result parser/comparator plus
  a read-only parent CLI. It reads exactly three caller-named retained artifacts,
  hashes the complete bytes from each open file, retains bounded parse prefixes,
  and emits one JSON result to stdout. No process, network, target, project
  helper, input parser or expected-value channel to a child exists.
- `qualify_comparator.py`: exact-buffer source loader and finite synthetic
  controls. After explicit source-hash admission it compiles/executes that exact
  reviewed comparator buffer as a non-main module, avoiding source/.pyc races.
  It creates one fresh caller-specified private scratch directory and temporary
  synthetic regular files inside it, then invokes the comparator main function
  in-process with captured stdout/stderr. It launches no subprocess. The temporary
  fixture files are removed; the scratch directory remains. JSON output records
  controls, observed classifications and the first failed control, if any.
- `AUTHORING.json` and `MANIFEST.sha256`: exact draft identities and no-execution
  declaration. They are not successful qualification receipts.

Imports are only Python standard library: argparse, contextlib, hashlib, io,
json, os, pathlib, re, stat, sys, tempfile and types. No repository import,
installation, native decoding or instruction evaluation is present. Parent
execution should use a directly admitted Python with `-I -B -S`.

## Result rules

`compare_bytes(expected, actual, process_exit, stderr)` first checks caller types
and expected grammar. A recorded nonzero child exit or nonempty stderr is a
process qualification failure, even if stdout happens to match. Actual output
must then be complete ASCII/LF result grammar with unique exact IDs, at most8192
rows, canonical u64 sums, statuses `ok`/`bounds`/`order` and boolean exactly0/1.
CR/NUL/BOM/non-ASCII, empty/extra lines, noncanonical numbers and extra fields
are refused. The expected stream receives the same strict grammar checks.

Missing, extra, duplicate, reordered or replaced IDs are qualification failures;
they cannot count as value mismatches. Only complete, well-formed, equal-count,
exactly aligned streams reach value comparison. A changed status or any changed
sum/boolean then contributes one semantic mismatch for that row. The report
counts every mismatch and retains up to eight examples. It never recalculates
the predicate, imposes B<=S, or imposes a relation between status and numbers.

The derived output bound is8192*112=917504bytes. A maximal success row is64 ID
bytes+four tabs+`ok`+two20-digit sums+one boolean+LF. One byte beyond that limit
is retained during file reads to ensure oversize data cannot be silently
truncated into a match. Each complete artifact is still hashed. Stderr retains
only a nonempty witness for comparison, while metadata binds its full length
and hash. Supplied hashes authenticate the compared buffers; they do not prove
which process generated them.

Exit0 means match; exit1 means complete valid outputs differ in values; exit2
means qualification/artifact/CLI failure. The comparator does not itself launch
or observe a child. Its `--exit-code` must come from the actual retained child
receipt. Source/build/binary/stdout binding remains a parent-runner obligation.
These codes are the comparator's codes, not the driver's malformed-input policy.

## Planned controls, not observed results

The finite source enumerates90 planned synthetic checks. No control has run.
The synthetic rows are transport-only scalar text; none claims a native stake
expected result. Planned controls cover:

- Equal mixed statuses, empty stream, case-distinct IDs and arbitrary canonical
  pairs including B>S and an intentionally unrelated boolean.
- Isolated selected/total/boolean/status changes, including the final row and
  several mismatches, that must be genuine `value_mismatch` outcomes.
- Missing/extra/duplicate/reordered/replaced/case-changed IDs; malformed expected
  streams; process exits, signal-style negative exits, stderr and precedence.
- Canonical fields, LF/ASCII, ID syntax/length, status/field counts, both sum
  fields at bad signs/leading zeros/whitespace/overflow and invalid booleans.
- Synthetic output at8192 rows and its derived917504byte maximum, plus one-over
  refusals. These are output-parser tests, not source-driver input resource tests.
- Actual parent CLI entrypoint for matching/value/duplicate/process/stderr
  outcomes, separate expected/actual/stderr pin failures, missing-file I/O,
  unknown arguments and prefix retention versus whole-file hash/length.

Pure digest checks are not substituted for the separate integrated CLI pin
controls. There are no instruction mutants, captured evaluators, target cases,
real driver runs or source builds. Actual input transport qualification is a
separate future stage. No equivalent post-saturation early-stop mutation is
invented here.

## Interfaces for later admitted execution

The parent retains raw child stdout/stderr and actual exit before comparison.
It never supplies expected data or filenames to the future input-only driver.
Replace every capitalized path/pin below with an authenticated concrete value.

```sh
python3 -I -B -S compare_results.py \
  --expected EXPECTED.tsv --expected-sha256 EXPECTED_SHA256 \
  --actual CHILD.stdout --actual-sha256 STDOUT_SHA256 \
  --stderr CHILD.stderr --stderr-sha256 STDERR_SHA256 \
  --exit-code ACTUAL_RECORDED_CHILD_EXIT

python3 -I -B -S qualify_comparator.py \
  --comparator compare_results.py --sha256 COMPARATOR_SOURCE_SHA256 \
  --scratch /ABSOLUTE/FRESH/PRIVATE/B20/SCRATCH
```

Do not execute these commands until parent source/effect review admits them.
There is no public packet edit, source/model/corpus authorization or gate claim.
