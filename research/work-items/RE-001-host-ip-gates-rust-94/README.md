# RE-001: node94-host-ip-gates

## Question and result

The maintained static packet binds three host-IP query callers and the override branch but has no Rust projection. This implements the selected caller predicate: unsigned length at most 15, odd parser AL and zero remainder admit to collection; length rejection precedes parser-result rejection. Exactly 2^63 selects the fallback probe route for the supplied override word.

- Component: foundation / selected node runtime.
- Main base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Maintained prior findings: `research/work-items/RE-001-host-ip-admission-94/` and `tools/host_ip_admission.py` at the base above. These project-authored observations are credited inputs, not repeated new discoveries. No unlicensed inferred reference source is copied.
- Claim status: captured bytes/FDEs/operands are observations; selected new API and labels are inferred projections; effectful helpers and integration remain unresolved.

## Evidence

All coordinates are ELF virtual addresses; ends are exclusive. Reproduction authenticates the entire input and regenerates maintained static observations, owner body hashes and unique non-overlapping FDEs. Complete LLVM listings agree with independent Capstone byte partitions without masks:

| Start | End exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| `0x13ca370` | `0x13cba3e` | 5,838 | 1,120 |

These are retained disassembly denominators, not a claim to implement every owner path. Only contiguous standalone LLVM LOCK display prefixes are joined; no bytes are omitted. Evidence/source-tool digests and helper/data/relocation records are retained in `evidence.json`.

## Implementation and comparison

New safe `no_std` Rust is built directly with rustc 1.94.1, edition 2021, no dependencies or invented root Cargo workspace. Only this new library and host harness execute. The captured node is never executed.

Before Rust existed, `verify.py --prepare` froze corpus inputs and expectations and refused preparation if the implementation existed.

The 62,440 rows cover: All 256 AL values at ten unsigned length boundaries, four remainder classes and six override boundaries, plus 1,000 seeded full-width cases. A separately written arithmetic truth table cross-checks the maintained caller model.

The independently linked harness receives inputs only. Debug, optimized and repeated optimized builds each match all rows exactly. Warnings are denied; overflow checks are enabled. Repeated optimized library digests agree and the focused own Rust boundary/precedence test passes. Every separately compiled mutant completes the normal protocol and disagrees:

| Semantic mutation | Mismatching rows |
| --- | ---: |
| length_off_by_one | 6,144 |
| low_bit_full_byte | 3,048 |
| invert_remainder | 12,288 |
| wrong_override_sentinel | 20,480 |
| length_precedence | 31,720 |

`results.json` retains compiler/source/verifier/harness/corpus/output/library digests, counts, boundaries and control outcomes. Raw inputs, expectations, commands/compiler logs and every runner output are kept in ignored `work/` and reproduce deterministically. Finite comparisons are conditional static-derived checks, not target differential execution or original code/ABI equivalence.

## Reproduce

```sh
python3 -B research/work-items/RE-001-host-ip-gates-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/node94-host-ip-gates-fresh --controls
python3 -B -m unittest discover -s tests -p test_host_ip_admission.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a fresh output directory. Observed environment: macOS arm64; Python 3.14.5; Capstone 5.0.7; LLVM 23.1.4; GNU binutils 2.45 with x86 ELF support; Git LFS 3.8.1; GnuPG 2.5.24; rustc 1.94.1. `6` existing focused methods pass. Required checks pass; full shared validation scope is in `VALIDATION.md`. No hosted CI or independent review result is claimed.

## Limits and next question

The library consumes supplied raw outcomes. It does not perform endpoint queries, commands, override-file reads, IP parsing, collection insertion, timeout handling, output formatting, allocation or unwind. Synthetic parser results need not be reachable from a real parser. No endpoint or captured executable runs.

No progress gate, imported pin, registry, dependency, captured executable, networking, chain action, signing, private fixture or optional usage/trace upload changes. Full component acceptance gates remain false.

Next: Close parser 0x1573af0 and its concrete return protocol before claiming accepted-address grammar.
