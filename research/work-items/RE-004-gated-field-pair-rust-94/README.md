# RE-004: same-flag field-copy pair in safe Rust

Target node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`;
reference gitlink `999556f6e0a474b8312db96ec3149e1c44e97c23` unchanged.
Bounded RE-004/foundation additional research; no component, coverage or progress
gate advances. Node115 and visor are separate targets.

The new `src/node94-gated-field-pair` library reconstructs both complete leaves
at 0x53b1120 and 0x53b1150 (72 bytes, 18 instructions). The first checks a pointer
then a byte gate, copying two nonadjacent source qwords to an external pair.
The second uses the same byte gate to copy that external pair into an object
field. Full RAX/RDX and all final image bytes are preserved, including arbitrary
unaligned aliases and absent unused fields. All nonzero gate bytes enable the
copy; the return is not a boolean. The prior static packet
`foundation-gated-two-field-copy-94` covered only the first and expressly excluded
the second. This PR closes them together, without changing historical evidence.

PROOF.md derives every path, register width, ordered read and store directly
from complete instructions. Both members read all needed source values before
their first store. A safe nonwrapping byte image models arbitrary data aliases;
numeric addresses never become host pointers. Missing reached memory produces
a new refusal with no writes. The original normal-return/stable-memory premises,
excluded fault/MMIO/concurrency/control effects and unprojected XMM0 are explicit.
No guessed source type, inferred unlicensed implementation or helper stub is used.

## Evidence and qualification

GNU, Apple LLVM and Capstone agree on all 72 bytes and 18 boundaries. Actual
FDE/CIE records, branch/RET lists and 6/2 padding bytes are bound independently.
Both raw-zero RELATIVE slots have unique full-width writers. All 80,300 RELA
records and complete .text E8/E9 candidates are checked; no direct entry target,
called helper or RIP-relative data dependency exists. This is not a complete
indirect-reference census. All 43 structural controls reject corruption without
relying on the initial whole-artifact digest check.

An immutable-address-map oracle and 5,834 cases were frozen before Rust existed.
Four actual opt0/opt3 builds and repeats matched all 23,336 outputs: 17,840 admitted
projections plus 5,496 new API refusals. Every output byte is compared, including
the inactive image suffix. The input-only client receives no expectations.
All 28 compiled wrong implementations produce mismatches, including eager gate
and source reads, wrong widths/offsets, booleanized returns, partial-register
clobbers, endian errors and an early store that destroys the second source.
Three units per optimization, malformed input and comparator controls pass.
Same-option rlib/client/output hashes repeat exactly. No native build/control
failure occurred. All 214 original stdout/stderr streams and exact commands are
retained in a lossless content-addressed archive (gzip level1,mtime0).

The compiler is rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, binary SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Builds pin aarch64-apple-darwin, edition2024, denied warnings, overflow checks,
one codegen unit, panic abort for value builds and the actual system linker.
GNU 2.47.20260726, Apple LLVM 17 and Capstone 5.0.7 supply static evidence.
Only new native Rust executes. Captured execution/emulation, original ABI,
original compiled-byte identity and whole-node behavior remain unclaimed.

```sh
python3 -O -B research/work-items/RE-004-gated-field-pair-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-gated-field-pair-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/gated-field-pair-replay
```

Use a new output directory. Compiler location may differ; version and binary
hash remain checked. Exact source hashes, raw streams, mutants and first
mismatch witnesses are retained. Static instruction bytes are evidence locks,
never an executable transplantation or Rust implementation.

## Repository verification limits

The first doctor attempt selected Apple objdump and lacked GNU readelf on the
default PATH. It stopped before other checks; its exact stdout/stderr and exit2
are preserved. The retry explicitly prepends the already installed GNU binutils
and rustup directories. No dependency or repository tool was changed.

The separate shared baseline attempted 971 files/15,462 tests/69 skips. Original
exit2 was solely three disk-full errors; all 20 affected tests passed isolated
retries. `shared-baseline-result.json` retains that result and log hashes. It is
not a successful full-sweep repeat, per-head full suite, skipped Linux execution
or hosted CI success. Imported pins and generated acceptance gates stay unchanged.

Doctor with corrected PATH, verify, catalogue-check, reproduce, all 29 focused predecessor/FDE/GNU tests and rustfmt passed. Exact commands, outputs and initial doctor failure are retained in repository-checks.json.gz.

## Independent review

A separate reviewer re-read the full Rust source, driver and proof, independently parsed all 121,299 FDEs, three CIEs and 80,300 RELAs, and authenticated both complete bodies and actual slot writers. An immutable interval/action calculation, without importing the oracle, matched all 5,834 frozen outputs and every gate byte for each member. The reviewer reran all 43 structural controls. The portable script and hash-bound result are retained; the parent replay produced the identical report. No independent native rerun or exhaustive image enumeration is implied.
