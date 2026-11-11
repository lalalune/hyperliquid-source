# Actual checks and limits

Native freeze succeeded42.703s after two failed attempts38.196/39.550s;
observer smoke5.183s failed, corrected smoke5.190s passed. All those raw logs
remain compressed and external originals are retained. The pre-Rust seven
focused tests passed6.457s. Pre-Rust seal3b7e035c contains no Rust source.

The actual Rust pipeline passed356.278s: opt0/3/repeat all3,373 rows exact,
same-path opt3 rlib bytes repeat,140 sealed client cases and12 compiled wrong
sources all ordinary assertion101 with complete streams. See rust-results.json
and exact full receipt/archive. Successful binaries are owned research builds,
not original captured executables.

The first scoped run failed2.082s because its test pattern mistakenly named
`test_node115_adjacent_last.py`, running zero tests. The corrected pattern
`test_adjacent_last115.py` passed in the complete421.098s run:

focused=7.476s; fmt=2.824s; clippy=6.194s; scope-gates=55.763s; doctor=9.294s; verify=77.473s; catalogue=62.009s; catalogue-check=60.467s; reproduce=133.353s

The focused run executes7 tests; packet integrity executes12. Fmt covers
library, input-only driver and exact client fixture; Clippy uses-Dwarnings.
`make reproduce` ran with the original baseline helper. macOS make emitted
xcrun cache-write warnings in its restricted temporary folder but returned0;
these warnings are preserved, not hidden or treated as a build proof.

Only catalogue generation/check temporarily uses the separately submitted
#2655 snapshot helper (measured39.47GB repeat-read blocker), restored before
reproduce and final checks. validation-overlay.json records both hashes and
commands. This is explicitly not an unmodified-head local catalogue claim;
the helper is absent from this PR. Previous exact-tree sibling CI is shared
context, not a current-head full-suite pass. Own upstream CI is pending;
no full local make test is claimed. All92 gates remainfalse.

New scope: one consensus implementation path. Generated catalogue561 packets,
35 Rust areas,19 Cargo manifests. Base actually has560 tracked top-level
packet READMEs despite stale generated559; no phantom second packet is added.
No byte-window registration, root workspace, Linux build, original ABI,
whole-consensus integration or production NaN/admission policy is claimed.
