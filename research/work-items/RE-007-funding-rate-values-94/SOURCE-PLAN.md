# Production and validation plan — source not yet authorized

Construct exactly one dependency-free Cargo crate, `src/node94-funding-rate-values`, after the root pre-source gate. The crate will have `Cargo.toml`, an actual offline-generated `Cargo.lock`, `README.md`, `src/lib.rs` and focused tests. No root workspace or existing crate is changed. A `no_std` library is appropriate: the rate borrows a supplied slice and need not allocate. No dependency on unmerged funding crates or an external floating-point package is planned.

Proposed public operations:

```text
funding_rate_bits(samples: Option<&[u64]>,
                  interest_bits: Option<u64>,
                  multiplier_bits: Option<u64>,
                  clamp_bits: u64) -> Option<u64>
insertion_bits(rate: Option<u64>) -> u64
```

The second operation is exactly the observed caller's absence-to+0 projection. It does not insert into a map. Private binary64 operations implement only the value relation needed by this family, with integer significands, bounded shifts, sticky/remainder information and nearest-even rounding. They will not be exposed as a generic floating-point library. Source must preserve exact NaN bits and operation order; it must not use host `f64` arithmetic, reassociate the sum or canonicalize outputs.

Before first compilation, freeze the actual crate files, real lockfile, input-only client, source proof, harness and complete qualified toolchain/dependency graph. Reject symlinks in admitted source/harness paths. Build in fresh canonical-resolved temporary directories, auditing both lexical and canonical Cargo ancestor/config paths and recording source-tree ancestor context. Do not silently build in the user's workspace. Only pinned already-installed Rust may run, offline/locked, with explicit environment and no network/install step.

Qualification must retain every real command and compressed raw stdout/stderr stream, including any failure. Run focused actual-crate tests and format/Clippy checks, all frozen3153 outputs in debug/release, and clean same-source rebuilds. Compare both library and input-client artifacts honestly across directories, keeping raw differences and remap limitations visible. Only the outer comparator reads expectations. Compare all complete value streams exactly.

Compile a justified set of incorrect source variants against the actual graph: sum seed/order or bulk-tail omission, default selection, early absence, wrong division/rounding, NaN priority/canonicalization, clamp order/finite guard/signed-zero handling, multiplier and final factor, and caller absence projection as applicable. Each claimed distinguished mutant must actually compile, run and emit a complete stream that differs. An equivalent or unobserved variant must be reported as such rather than counted as a killed bug. Include actual comparator corruption and malformed-input/empty-stream controls.

If a frozen corpus misses a distinguishing case, preserve that initial result and every existing source/oracle freeze. Any new expectation requires an independently justified, explicitly post-source supplement and separate root admission before continuation; do not relabel it pre-source. Root independently reviews and runs the final harness. Full captured execution, instruction emulation, native ABI/compiler/byte identity, live policy and component gate advances remain excluded.
