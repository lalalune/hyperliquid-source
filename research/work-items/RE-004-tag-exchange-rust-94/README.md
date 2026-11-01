# RE-004: atomic tag-byte exchange with full register observations

This adds a safe `no_std` Rust reconstruction of node94's complete
`[0x4f7fb20,0x4f7fb38)` leaf. The foundation-tiny-tag-swap packet identified
its byte exchange. This contribution preserves that atomic operation,
closes full RAX/RCX and numeric field-address observations, and adds
independent values, concurrent host tests and compiler-IR qualification.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The reference gitlink stays
`999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred upstream source was
read or copied. OpenAI / Codex authored the work; exact runtime model
identity is not exposed. New implementation and prose are MIT.

## Bounded relation

The low tag byte selects 0 for zero, 2 for two and 1 otherwise. One
SeqCst `AtomicU8::swap` replaces the field byte and returns its previous
value in full RAX; full RCX is zero. The API also reports original
`object+16` modulo 2^64. This numeric address is not used to dereference
the supplied Rust cell. With concurrent exchanges, the replaced value is
observed at the exchange, not necessarily at function entry or return.

[PROOF.md](PROOF.md) derives the complete byte partition, partial-register
effects, atomic memory operand and source correspondence. It cites the
Intel XCHG specification and pinned Rust atomic documentation. Original
ABI, flags, faults, MMIO, code/control aliases, other-memory interactions
and arbitrary whole-program memory-model equivalence are excluded.

All 24 bytes, nine instruction boundaries, eight padding bytes, actual
FDE/CIE and 36 raw-zero RELATIVE entry slots are bound. Every one of
80,300 RELA records is checked for conflicting writers, including partial
overlaps and other addends. GNU, LLVM and Capstone agree. E8/E9 scans are
empty; this is not a complete indirect-reference census. Twenty-one
structural corruption controls reject under optimized Python.

## Values and atomic qualification

Before Rust existed, 76,240 isolated cases were frozen, covering all
65,536 low-tag/old-byte pair plus ignored high bits and wrapped addresses.
All 304,960 observations match four opt0/opt3 repeat builds; same-opt
rlib/client/output hashes agree. Seventeen compiled value mutants differ.

Two additional compiled controls deliberately preserve every isolated
value: weakened atomic ordering and split atomic load/store. Both are
rejected by a separate IR check requiring exactly one SeqCst byte
`atomicrmw xchg` and no separate atomic load/store or cmpxchg. The command
pins `link-dead-code=yes` to retain the public function in optimized
library IR. These are IR controls, not claimed value-corpus detections.
Three unit tests pass per profile, including 64 three-thread rounds that
check complete old-byte/final-byte histories against all six serial orders.
This finite host test does not exhaust schedules or establish equivalence
for other memory or other compilers.

An independent reviewer rederived all fixtures using a literal byte table,
manually parsed ELF/RELA and verified every entry slot. The source/proof
review and static replay found no blocker. `compression-peer-review.json`
binds the versions actually reviewed; `verify_independent.py` changes only
repository/output paths, and its replay retains the same numeric/static
checks. Final native qualification is recorded separately.

## Retained interruptions and final result

The first qualification stopped because one mutant's unnecessary
parentheses failed `-D warnings`. The second stopped because another
mutant lost u8 type inference. These were control compilation errors;
the correct source builds and tests had passed. Both exact validators,
commands, compiler diagnostics, traceback logs, generated mutant sources
and artifact hashes remain under `initial/` and `initial-second/`.
Their archives contain 73 and 101 exact stream/artifact entries.

Only mutant spellings/type annotations and a unique replacement anchor
were corrected. The library, oracle, static facts and frozen expectations
did not change. All seventeen mutant variants were then typechecked, and
a fresh complete qualification passed. The final archive has 166 exact
command streams and three emitted IR artifacts, each verified against its
raw bytes and SHA-256. Gzip uses level 1 and mtime 0. Source/compiler,
commands, artifacts, comparisons and structural results are recorded in
`native-result.json` and `native-commands.json`.

Eight predecessor tests, rustfmt, doctor, verify, catalogue-check and
reproduce pass. The separate shared baseline reported 15,462 tests in
971 files with 69 skips and exited 2 from three disk-full errors. All 20
affected tests passed isolated retries. This is not a successful full-sweep
rerun, per-head full-suite result or qualification of skipped Linux cases.

## Reproduction

Use unchanged materialized pins and a new output directory:

```sh
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
python3 -B -m unittest tests.test_foundation_tiny_tag_swap -v
python3 -O research/work-items/RE-004-tag-exchange-rust-94/verify_static.py
python3 -O research/work-items/RE-004-tag-exchange-rust-94/verify_independent.py
python3 -O research/work-items/RE-004-tag-exchange-rust-94/verify_rust.py \
  --out work/tag-exchange-review \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc
```

The compiler pin is rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8, SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The observed host is macOS arm64 with Python 3.14.3, Capstone 5.0.7 and
GNU binutils 2.47.20260726. No captured executable or instruction emulator
was run. Original byte identity, source identity, whole-node equivalence,
component gates and hosted CI success are not claimed. Pins, prior
evidence, generated catalogues and progress remain unchanged.
