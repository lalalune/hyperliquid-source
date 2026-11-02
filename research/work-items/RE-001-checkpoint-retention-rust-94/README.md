# Selected checkpoint row retention: bounded independent Rust implementation

- Task/component: RE-001 / abci checkpoint row policy.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: `e5c9b6436876b2a4a39daef813171f9879317699`. Reference pin stays `999556f6e0a474b8312db96ec3149e1c44e97c23`; inferred unlicensed code was not copied or used as implementation authority.
- Before: the maintained [RE-001-checkpoint-retention-94](../RE-001-checkpoint-retention-94/README.md) packet established this selected policy, but no corresponding independent Rust implementation existed in `src/`. After: buildable safe Rust, an external comparison harness and reproducible target-bound validation. No new discovery credit or progress gate is requested.

## Evidence and implementation scope

The 595-byte FDE-described owner at ELF VA `[0x33084a0,0x33086f3)` copies selected 32-byte rows. A nonzero marker-helper AL keeps a row unconditionally, irrespective of height bounds. Otherwise a height below lower requests an opaque diagnostic. Conditional on that helper returning normally, keep iff `lower <= height < upper && height <= cap`, all unsigned.

`decide` recovers that selected keep/diagnostic policy. `height` reads the observed little-endian word at row+0x18. `retained_row` returns a kept 32-byte row unchanged, preserving all opaque bytes. These interfaces and `Option`/`Decision` types are new safe Rust, not the original iterator/ABI or an allocation/ownership proof.

A nonzero marker is not permission to delete a file. Filesystem marker determination, the diagnostic's effects/nonreturn paths, allocation, iterator ownership, callers and the complete checkpoint lifecycle remain excluded. The marker result is supplied as a raw byte; no filesystem/helper callback runs.

`verify.py` authenticates the complete input before calling the existing maintained static analyzer. Fresh records must equal `evidence.json`. Those checks bind the original code/data operands, FDE ranges, branches and relevant supporting records. Existing retained native disassembly remains the review source; this contribution neither copies it into machine-code output nor claims new decoding or helper closure. All addresses are original ELF VAs, not guessed runtime addresses.

## Reproduce

With pinned captures materialized, from the repository root:

```sh
python3 -B research/work-items/RE-001-checkpoint-retention-rust-94/verify.py --rustc /path/to/rustc-1.94.1 --output work/node94-checkpoint-retention-new --controls
```

The output directory must not exist. The production source is `src/node94-checkpoint-retention/lib.rs`. Builds invoke rustc 1.94.1 (`e408947bf`, LLVM 21.1.8) directly with edition 2021, `-D warnings`, `-C overflow-checks=on` and optimization levels 0/3. No Cargo.lock is needed because no Cargo project or external dependencies are introduced. Host: macOS arm64, Python 3.11.15. Host ARM code is not compared to the original x86-64 ELF.

The separate harness receives input words/bytes only. Python retains the expected stream and checks all output lines. This is data-flow separation, not OS sandbox isolation. A ten-point u64 boundary set supplies all 10,000 unmarked height/lower/upper/cap combinations. All 256 marker-byte values are checked against selected boundary cases, followed by seeded full-width samples and 768 opaque-row preservation probes. Unmarked expectations are obtained from the maintained selected CMP/Jcc interpreter and checked against an independent order formula. This is synthetic static interpretation, not native captured-code execution.

## Observed results

- 12,304 cases per debug, optimized and repeated optimized runner: zero mismatches.
- Both own optimized `.rlib` builds are byte-identical, proving repeatability of this host library only.
- Own Rust unit tests pass; full output is `unit-tests.txt`.
- All 6 independently compiled semantic mutants are detected. The runner changes production code only, leaves test source intact and compares the external output. Results include each mismatch count, compiler identity and source/corpus/output digests.
- Existing static checks and required repository checks are recorded in VALIDATION.md when complete. No broader pass is inferred from the focused results.

## Limits and next work

This is a selected policy implementation over raw scalars/valid byte slices, not a complete recovered subsystem, original ABI or runtime-equivalence claim. Existing decoded semantics remain the proof boundary, and finite examples do not establish whole-node correctness. No filesystem deletion, marker query, captured executable or unknown diagnostic helper runs. Original imports, captures, tools, reference pins and all component gates remain unchanged.

Next recover and validate the excluded producer/helper/caller contracts before joining this policy into a full node path.
