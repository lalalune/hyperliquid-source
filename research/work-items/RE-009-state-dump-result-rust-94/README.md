# RE-009: node94-state-dump-result

## Question and result

The baseline packet proves the state-dump helper integer projection but has no independent Rust implementation. This adds the raw status gate, signed64 Euclidean quotient/remainder by 86400, signed32 index guard after offset 719163, zero-callee rejection, and the three normal-return DWORD values [supplied callee EAX, Euclidean remainder, retained DWORD]. Rust division is justified by the existing full signed64 multiplier/shift theorem, regenerated from captured operands.

- Component: storage/state roots.
- Main base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Maintained prior findings: `research/work-items/RE-009-state-dump-result-projection-94/` and `tools/state_dump_result_projection_static.py` at the base above. These project-authored observations are credited inputs, not repeated new discoveries. No unlicensed inferred reference source is copied.
- Claim status: captured bytes/FDEs/operands are observations; selected new API and labels are inferred projections; effectful helpers and integration remain unresolved.

## Evidence

All coordinates are ELF virtual addresses; ends are exclusive. Reproduction authenticates the entire input and regenerates maintained static observations, owner body hashes and unique non-overlapping FDEs. Complete LLVM listings agree with independent Capstone byte partitions without masks:

| Start | End exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| `0x151cba0` | `0x151cca5` | 261 | 64 |
| `0x46cea60` | `0x46cf026` | 1,478 | 299 |

These are retained disassembly denominators, not a claim to implement every owner path. Only contiguous standalone LLVM LOCK display prefixes are joined; no bytes are omitted. Evidence/source-tool digests and helper/data/relocation records are retained in `evidence.json`.

The complete caller FDE listing is context, not newly discovered code or a claim to implement all its paths. The prior helper prefix credited to #521 and actual consumer credited to #1019 retain their attribution. `evidence.json` regenerates the prior packet's multiplier approximation proof, guard identity, three writes and actual consumer permutation; this PR adds the safe scalar Rust projection only.

## Implementation and comparison

New safe `no_std` Rust is built directly with rustc 1.94.1, edition 2021, no dependencies or invented root Cargo workspace. Only this new library and host harness execute. The captured node is never executed.

Before Rust existed, `verify.py --prepare` froze corpus inputs and expectations and refused preparation if the implementation existed.

The 13,168 rows cover: Signed64 extrema, negative and positive divisor boundaries, both signed32 index endpoints and neighboring quotient/remainder values, six raw status classes, four retained/result words and 10,000 seeded full-width cases. The maintained multiply/shift equations are cross-checked with independent Python Euclidean divmod and signed-range arithmetic.

The independently linked harness receives inputs only. Debug, optimized and repeated optimized builds each match all rows exactly. Warnings are denied; overflow checks are enabled. Repeated optimized library digests agree and the focused own Rust boundary/precedence test passes. Every separately compiled mutant completes the normal protocol and disagrees:

| Semantic mutation | Mismatching rows |
| --- | ---: |
| truncating_remainder | 420 |
| truncating_quotient | 720 |
| wrong_index_offset | 2,080 |
| excluded_status_low_bit | 6,520 |
| zero_result_inversion | 1,840 |
| swap_output_fields | 1,155 |
| wrong_low_guard | 240 |
| wrong_high_guard | 240 |

`results.json` retains compiler/source/verifier/harness/corpus/output/library digests, counts, boundaries and control outcomes. Raw inputs, expectations, commands/compiler logs and every runner output are kept in ignored `work/` and reproduce deterministically. Finite comparisons are conditional static-derived checks, not target differential execution or original code/ABI equivalence.

## Reproduce

```sh
python3 -B research/work-items/RE-009-state-dump-result-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/node94-state-dump-result-fresh --controls
python3 -B -m unittest discover -s tests -p test_state_dump_result_projection_static.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a fresh output directory. Observed environment: macOS arm64; Python 3.14.5; Capstone 5.0.7; LLVM 23.1.4; GNU binutils 2.45 with x86 ELF support; Git LFS 3.8.1; GnuPG 2.5.24; rustc 1.94.1. `13` existing focused methods pass. Required checks pass; full shared validation scope is in `VALIDATION.md`. No hosted CI or independent review result is claimed.

## Limits and next question

The earlier helper, index callee 0x151f6f0, calendar meaning/units, real input reachability, concrete types, diagnostic/error-call effects, alias/concurrent frame mutation, ownership/unwind and original ABI remain unclosed. The API emits an index only when the selected native guard permits the opaque call, and fields only on the normal-return route. The actual caller field permutation is retained static context, not implemented memory stores.

No progress gate, imported pin, registry, dependency, captured executable, networking, chain action, signing, private fixture or optional usage/trace upload changes. Full component acceptance gates remain false.

Next: Close the index callee result contract and upstream input reachability before assigning calendar types or composing a storage workflow.
