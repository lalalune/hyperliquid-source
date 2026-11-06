# Actual validation

Native freeze24.021s passed6741 distinct inputs,76B25selected/allvisited,
full113B33instruction context,9output-changing actual-byte controls and3rejections.
Pre-Rust focused7 tests passed5.978s (inner4.665). Native evaluator, contract,
inputs/expected and actual controls were sealed atb73a15630a1406d0c9ac9ab1f021f9c856a4c69b
before any Rust source existed.

Rust pipeline211.390s passed opt0/3 and same-path opt3 rlib/output repetition,
all6741 complete observations,116sealed clientcases and12compiledmutants.
Every mutated source emitted a complete stream and failed ordinary assertions101;
see rust-results.json for mismatch counts and lossless full receipts. No crash
or evaluator failure is counted as an output match or successful source control.
Research tools: Python3.12.14/Capstone5.0.6/GNUobjdump2.47.20260726,
macOSarm64 rustc1.94.1/LLVM21.1.8 edition2021. This is not the original compiler
recipe or a Linux build.

Scoped commands, all exit0:

focused=6.964s; fmt=2.594s; clippy=6.679s; scope-gates=55.019s; doctor=8.797s; verify=68.961s; catalogue=66.914s; catalogue-check=60.702s; reproduce=128.17s

Focused7 tests, fmt covering library/driver/exactfixture, Clippy-Dwarnings,
12 packet-integrity tests, doctor/verify/catalogue/check/actualreproduce passed.
Raw compressed logs retain any macOS xcrun restricted-cache warnings; exit0 is
reported only from the actual command return. No full local make test or own
upstream CI pass is claimed; own upstream full CI is pending at submission.

Catalogue generation/check alone uses the separately submitted#2655 snapshot
helper for the measured39.47GB repeated-read blocker. Baseline helper is restored
before actual reproduce and final checks; both hashes/scope are in
validation-overlay.json. This is not an unmodified-head local catalogue claim.
No helper change is included in this PR. Earlier sibling CI is shared context,
not a current-head full-suite result.

The fixture generator's initial preparation had a brace typo and rustfmt saw
a missing fixture; corrected before all recorded source build/stream comparisons.
Sealed inputs/expected/native semantics were unchanged. No runtime test failure
or native oracle mismatch was suppressed.

Only one fees implementation path is added, all92 gates and byte registrations
unchanged. Base560tracked top-level packets differs from its stale generated559;
this single packet yields561. Rust areas34->35, Cargo manifests19 unchanged.
No original ABI, production table/nonfinite admission, MXCSR recovery, exception
flags/unwind, complete fees validity, target-byte equivalence or whole-node
integration is claimed. Complete input storage and width/state premises are in
CONTRACT.md. No captured process/Unicorn/live service/chain/signing is used.
