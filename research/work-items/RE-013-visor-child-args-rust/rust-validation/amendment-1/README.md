# Explicit first-build correction

The initial frozen library compiled. The first actual debug test compilation
then failed with E0308: a repeated `Option<&[u8; 0]>` array did not coerce to
`Option<&[u8]>`. The correction writes the empty value as `Some(&b""[..])`.
Production library code, API, expectations and all 23 pre-code files are unchanged.

The original SOURCE-FREEZE.json, build.py and verify.py remain byte-identical at
their original paths. Exact old test/README bytes, all 15 command receipts and
all raw streams are retained here. AMENDMENT.json records exact changes and
rehash results. No test success or mutant sensitivity is claimed for this run.

The amended source freeze is SOURCE-FREEZE-2.json. Use build_amended.py and
verify_amended.py for the current source; the frozen original harness README
records the earlier historical attempt. IMPLEMENTATION.md will record actual
completed results and the final commands after qualification.
