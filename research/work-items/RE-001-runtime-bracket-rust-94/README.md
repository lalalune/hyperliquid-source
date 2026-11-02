# RE-001: node94-runtime-bracket

## Question and result

Four maintained node94 wrapper records establish a selected runtime state-cell bracket but no independent Rust implementation. This adds its conditional decision protocol: prior byte 2 fails before body entry; otherwise the body state is 2; missing context and non-2 post-state fail without restoring; a valid post-state restores the prior byte. The saved flag word and cleared low byte are projected separately.

- Component: foundation / selected node runtime.
- Main base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Maintained prior findings: `research/work-items/RE-001-runtime-state-brackets-94/` and `tools/runtime_state_static.py` at the base above. These project-authored observations are credited inputs, not repeated new discoveries. No unlicensed inferred reference source is copied.
- Claim status: captured bytes/FDEs/operands are observations; selected new API and labels are inferred projections; effectful helpers and integration remain unresolved.

## Evidence

All coordinates are ELF virtual addresses; ends are exclusive. Reproduction authenticates the entire input and regenerates maintained static observations, owner body hashes and unique non-overlapping FDEs. Complete LLVM listings agree with independent Capstone byte partitions without masks:

| Start | End exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| `0x28302f0` | `0x283069c` | 940 | 215 |
| `0x28306a0` | `0x2830a4c` | 940 | 215 |
| `0x2830a50` | `0x2830e18` | 968 | 224 |
| `0x2830e20` | `0x28313ec` | 1,484 | 315 |

These are retained disassembly denominators, not a claim to implement every owner path. Only contiguous standalone LLVM LOCK display prefixes are joined; no bytes are omitted. Evidence/source-tool digests and helper/data/relocation records are retained in `evidence.json`.

## Implementation and comparison

New safe `no_std` Rust is built directly with rustc 1.94.1, edition 2021, no dependencies or invented root Cargo workspace. Only this new library and host harness execute. The captured node is never executed.

Before Rust existed, `verify.py --prepare` froze corpus inputs and expectations and refused preparation if the implementation existed. `corpus-before-rust.json` retains the original pre-source descriptor. After initial control substitution failed to select exactly one formatted occurrence, only the mutation substitution was corrected; original input/expectation counts and digests remain identical.

The 196,608 rows cover: Every prior/after raw-byte pair with both context-presence states (131,072 rows), plus every u16 flag word (65,536 rows). The static model is checked against a separate route truth table and high-byte arithmetic formulation.

The independently linked harness receives inputs only. Debug, optimized and repeated optimized builds each match all rows exactly. Warnings are denied; overflow checks are enabled. Repeated optimized library digests agree and the focused own Rust boundary/precedence test passes. Every separately compiled mutant completes the normal protocol and disagrees:

| Semantic mutation | Mismatching rows |
| --- | ---: |
| wrong_prior_state | 1,024 |
| wrong_after_state | 66,046 |
| invert_context | 196,096 |
| wrong_enter_state | 196,096 |
| wrong_restore | 65,791 |
| wrong_flag_mask | 196,605 |

`results.json` retains compiler/source/verifier/harness/corpus/output/library digests, counts, boundaries and control outcomes. Raw inputs, expectations, commands/compiler logs and every runner output are kept in ignored `work/` and reproduce deterministically. Finite comparisons are conditional static-derived checks, not target differential execution or original code/ABI equivalence.

## Reproduce

```sh
python3 -B research/work-items/RE-001-runtime-bracket-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/node94-runtime-bracket-fresh --controls
python3 -B -m unittest discover -s tests -p test_runtime_state_static.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a fresh output directory. Observed environment: macOS arm64; Python 3.14.5; Capstone 5.0.7; LLVM 23.1.4; GNU binutils 2.45 with x86 ELF support; Git LFS 3.8.1; GnuPG 2.5.24; rustc 1.94.1. `6` existing focused methods pass. Required checks pass; full shared validation scope is in `VALIDATION.md`. No hosted CI or independent review result is claimed.

## Limits and next question

This is a pure projection conditional on reaching the selected bracket and normal body return, not a TLS implementation. Entry bypasses, initialization/destruction, actual body/scheduler/park effects, full flag restoration, native enum validity, panic behavior, unwinding and concurrency remain unproved. Body_state describes a selected store and does not execute a body.

No progress gate, imported pin, registry, dependency, captured executable, networking, chain action, signing, private fixture or optional usage/trace upload changes. Full component acceptance gates remain false.

Next: Establish the selected body and TLS-context helper effects before composing this bracket with a runtime implementation.
