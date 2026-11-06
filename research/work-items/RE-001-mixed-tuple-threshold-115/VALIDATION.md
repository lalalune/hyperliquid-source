# Actual validation and limits

Native43.631s PASS17847 family/input rows=5949 per original entry,300B84starts
allvisited,16outputCOW+2negative. Full exact100-byte encoding census finds
55ff9e0/2c6f290 for one encoding and55ff970 for the alternate layout. This
is one family, two unique encodings, three physical bodies. Sevenpretests
PASS5.707s (inner4.642). Sealb028a9e5f0353ddfad68146974d2d70a79ee1a1d
contains native/contract/goldens and no newRust.

Rust179.501s PASS opt0/3/repeat and17847 complete outputs; same-path opt3
rlib bytes repeat.186sealed clientcases. Twelve compiled mutants each emit
all17847 rows and fail normal assertions101; no crash counted as a control.
Mismatch counts:

{
  "unsigned-first": 3408,
  "signed-second": 1296,
  "signed-third": 1296,
  "strict-tuple": 1404,
  "strict-primary": 3654,
  "strict-fallback": 2637,
  "wrap-add": 1650,
  "lower-addend": 2388,
  "higher-addend": 1791,
  "primary-disjunction": 8586,
  "primary-code": 6564,
  "primary-word": 3321
}

Corrected scoped commands, all exit0:

focused=6.874s; fmt=2.635s; clippy=5.333s; scope-gates=51.306s; doctor=7.444s; verify=69.665s; catalogue=68.26s; catalogue-check=66.908s; reproduce=135.176s

Focused7, fmt(library/driver/exactfixture), Clippy-Dwarnings and12packetintegrity
tests passed. Initial scoped run2.430s failed because a reused runner selected
nonexistent test_node115_mixed_tuple_threshold.py (zero tests). Corrected
filename test_mixed_tuple_threshold115.py is above; source/evaluator/goldens
were not changed. Both failed and corrected rawlogs are retained.

Catalogue generation/check alone temporarily uses separately submitted#2655
snapshot helper due measured39.47GB repeat-read blocker. Both hashes/scope
are in validation-overlay.json; original baseline helper restored before actual
reproduce/final checks, no helper change is submitted. This is not an
unmodified-head local catalogue claim. Any macOS xcrun restricted-cache warnings
remain in raw logs; only actual command exits are reported.

Tools: Python3.12.14,Capstone5.0.6,GNUobjdump2.47.20260726; macOSarm64
rustc1.94.1/LLVM21.1.8 edition2021. No original compiler recipe, Linux execution,
ABI, financial/time meaning, complete caller validity, target-byte equivalence
or full component is claimed. Allocation to assets follows selected perp_meta.rs
caller context and does not prove leaf source ownership. All92gates/bytewindows
unchanged. Base560tracked packets vs stale generated559; one new packet561,
Rust areas34->35,Cargo manifests19 unchanged. Own upstream CI pending;
no full local make test or combined-node integration claim.
