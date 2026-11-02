# RE-001: node94-db-dir-guard

## Question and result

The baseline constructor packet establishes a checkpoint substring guard but leaves the vector candidate checks unmodeled and has no Rust implementation. This adds a safe byte-slice predicate and statically specializes helper 0x158ef30 to the captured nine-byte heckpoint verifier. Its three dword comparisons cover [0,4), [4,8) and [5,9); together with the candidate c/t mask they establish the ten-byte needle. Every failed candidate clears exactly one mask bit.

- Component: storage/state roots.
- Main base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Maintained prior findings: `research/work-items/RE-009-owned-db-dir-guard-94/` and `tools/owned_db_dir_guard.py` at the base above. These project-authored observations are credited inputs, not repeated new discoveries. No unlicensed inferred reference source is copied.
- Claim status: captured bytes/FDEs/operands are observations; selected new API and labels are inferred projections; effectful helpers and integration remain unresolved.

## Evidence

All coordinates are ELF virtual addresses; ends are exclusive. Reproduction authenticates the entire input and regenerates maintained static observations, owner body hashes and unique non-overlapping FDEs. Complete LLVM listings agree with independent Capstone byte partitions without masks:

| Start | End exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| `0x158e870` | `0x158ede9` | 1,401 | 286 |
| `0x158ef30` | `0x158f020` | 240 | 65 |

These are retained disassembly denominators, not a claim to implement every owner path. Only contiguous standalone LLVM LOCK display prefixes are joined; no bytes are omitted. Evidence/source-tool digests and helper/data/relocation records are retained in `evidence.json`.

The supplementary `search_evidence.py` authenticates operand pins in the helper and two caller setups. Ten below-identity single-byte operand corruptions are rejected. For all 65,535 nonzero 16-bit masks, its algebraic check verifies that ROL16(0xfffe, lowest-set-bit) removes exactly the selected bit. The retained proof explains the length-9 comparison partition and the caller OR preserving an earlier match. These are static arguments, not original instruction execution. Other generic helper lengths/short-byte arms are excluded.

## Implementation and comparison

New safe `no_std` Rust is built directly with rustc 1.94.1, edition 2021, no dependencies or invented root Cargo workspace. Only this new library and host harness execute. The captured node is never executed.

Before Rust existed, `verify.py --prepare` froze corpus inputs and expectations and refused preparation if the implementation existed. `corpus-before-rust.json` retains the original pre-source descriptor. After initial control substitution failed to select exactly one formatted occurrence, only the mutation substitution was corrected; original input/expectation counts and digests remain identical. The helper proof and its full FDE listing were added after the initial frozen corpus, closing a gap found while inspecting the complete constructor listing; Rust inputs, expected rows and source are unchanged.

The 19,491 rows cover: No-match and a planted match at every possible start for lengths 0..160 and selected block/tail boundaries through 1,024, every byte replacement in the ten-byte needle, binary/case/overlap cases and 1,000 seeded slices. The byte-bound start enumeration is cross-checked with independent substring membership.

The independently linked harness receives inputs only. Debug, optimized and repeated optimized builds each match all rows exactly. Warnings are denied; overflow checks are enabled. Repeated optimized library digests agree and the focused own Rust boundary/precedence test passes. Every separately compiled mutant completes the normal protocol and disagrees:

| Semantic mutation | Mismatching rows |
| --- | ---: |
| wrong_needle | 16,283 |
| prefix_only | 16,110 |
| suffix_only | 16,105 |
| miss_exact_length | 176 |
| case_fold | 12 |

`results.json` retains compiler/source/verifier/harness/corpus/output/library digests, counts, boundaries and control outcomes. Raw inputs, expectations, commands/compiler logs and every runner output are kept in ignored `work/` and reproduce deterministically. Finite comparisons are conditional static-derived checks, not target differential execution or original code/ABI equivalence.

## Reproduce

```sh
python3 -B research/work-items/RE-001-db-dir-guard-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/node94-db-dir-guard-fresh --controls
python3 -B -m unittest discover -s tests -p test_owned_db_dir_guard.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a fresh output directory. Observed environment: macOS arm64; Python 3.14.5; Capstone 5.0.7; LLVM 23.1.4; GNU binutils 2.45 with x86 ELF support; Git LFS 3.8.1; GnuPG 2.5.24; rustc 1.94.1. `34` existing focused methods pass. Required checks pass; full shared validation scope is in `VALIDATION.md`. No hosted CI or independent review result is claimed.

## Limits and next question

Outer-loop coverage is exhaustively established only for lengths 0..512, with additional finite corpus lengths through 1,024. The new byte-slice predicate is defined for all supplied slices, but all-usize target equivalence is not claimed. Valid regions, captured descriptor transfers and ordinary execution are premises. Filesystem/path normalization, native vector memory access/faults, singleton registry, ownership, panic/abort effects and original ABI remain excluded.

No progress gate, imported pin, registry, dependency, captured executable, networking, chain action, signing, private fixture or optional usage/trace upload changes. Full component acceptance gates remain false.

Next: Prove the outer 64-byte loop coverage for the full valid native length domain before claiming an unbounded equivalence theorem.
