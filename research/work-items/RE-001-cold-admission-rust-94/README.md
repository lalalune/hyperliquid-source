# RE-001: node94-cold-admission

## Question and result

The maintained static packet identifies cold-state digest and helper-result branches but has no independent Rust implementation. This adds a safe fixed-size digest comparison and the selected admission route: mismatch first; nonzero optional word with zero input word next; exact helper word 0x8000000000000040 permits the fetched-prefix route. Branch outcomes are descriptions rather than diagnostic, helper or trap execution.

- Component: foundation / selected node runtime.
- Main base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Maintained prior findings: `research/work-items/RE-001-cold-state-admission-94/` and `tools/cold_state_admission.py` at the base above. These project-authored observations are credited inputs, not repeated new discoveries. No unlicensed inferred reference source is copied.
- Claim status: captured bytes/FDEs/operands are observations; selected new API and labels are inferred projections; effectful helpers and integration remain unresolved.

## Evidence

All coordinates are ELF virtual addresses; ends are exclusive. Reproduction authenticates the entire input and regenerates maintained static observations, owner body hashes and unique non-overlapping FDEs. Complete LLVM listings agree with independent Capstone byte partitions without masks:

| Start | End exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| `0x23ecd70` | `0x23ed020` | 688 | 143 |
| `0x2209450` | `0x22095bd` | 365 | 87 |

These are retained disassembly denominators, not a claim to implement every owner path. Only contiguous standalone LLVM LOCK display prefixes are joined; no bytes are omitted. Evidence/source-tool digests and helper/data/relocation records are retained in `evidence.json`.

## Implementation and comparison

New safe `no_std` Rust is built directly with rustc 1.94.1, edition 2021, no dependencies or invented root Cargo workspace. Only this new library and host harness execute. The captured node is never executed.

Before Rust existed, `verify.py --prepare` froze corpus inputs and expectations and refused preparation if the implementation existed.

The 89,494 rows cover: Two equal digest patterns, every single-bit change over all 256 digest bits, seven raw-word boundaries in every selected word position, and 1,000 seeded combinations. The maintained byte-specialized SIMD comparison and route model are cross-checked with a separate array-equality/truth-table oracle.

The independently linked harness receives inputs only. Debug, optimized and repeated optimized builds each match all rows exactly. Warnings are denied; overflow checks are enabled. Repeated optimized library digests agree and the focused own Rust boundary/precedence test passes. Every separately compiled mutant completes the normal protocol and disagrees:

| Semantic mutation | Mismatching rows |
| --- | ---: |
| omit_upper_half | 43,904 |
| omit_lower_half | 43,904 |
| invert_digest | 89,494 |
| wrong_optional_test | 160 |
| wrong_input_test | 299 |
| wrong_helper_sentinel | 289 |

`results.json` retains compiler/source/verifier/harness/corpus/output/library digests, counts, boundaries and control outcomes. Raw inputs, expectations, commands/compiler logs and every runner output are kept in ignored `work/` and reproduce deterministically. Finite comparisons are conditional static-derived checks, not target differential execution or original code/ABI equivalence.

## Reproduce

```sh
python3 -B research/work-items/RE-001-cold-admission-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/node94-cold-admission-fresh --controls
python3 -B -m unittest discover -s tests -p test_cold_state_admission.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a fresh output directory. Observed environment: macOS arm64; Python 3.14.5; Capstone 5.0.7; LLVM 23.1.4; GNU binutils 2.45 with x86 ELF support; Git LFS 3.8.1; GnuPG 2.5.24; rustc 1.94.1. `6` existing focused methods pass. Required checks pass; full shared validation scope is in `VALIDATION.md`. No hosted CI or independent review result is claimed.

## Limits and next question

Fetch/hash/clone/validation helper internals, cryptographic or constant-time guarantees, concrete state types and reachability, diagnostic/trap effects, ownership/unwind and original ABI remain unclosed. ReturnFetchedPrefix denotes a route only; this library does not construct or return that native 56-byte state prefix.

No progress gate, imported pin, registry, dependency, captured executable, networking, chain action, signing, private fixture or optional usage/trace upload changes. Full component acceptance gates remain false.

Next: Close the opaque outer helper result protocol before implementing state-object ownership or effectful admission.
