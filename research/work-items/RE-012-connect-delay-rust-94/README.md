# RE-012 / node-runtime: node94-connect-delay

## Gap and recovered scope

The baseline has static evidence for per-candidate connect delays, but no independent Rust scalar implementation. This adds supplied map-value/list-index/list-length precedence and the measured delay arithmetic. A supplied map value, including zero, wins; otherwise use the list index or length. An absent snapshot returns +0.0. A present snapshot computes min(0.07, float(k) * (float(X) * 0.001)), preserving both conversions and multiply order. Snapshot wait/hold durations are not used by this selected arithmetic.

Base main: `e5c9b6436876b2a4a39daef813171f9879317699`. Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The existing project-authored producer `tools/gossip_connect_stagger_static.py` supplies maintained
byte/data/operand/relocation observations. Its fresh output and source digest
are retained in `evidence.json`; the unlicensed reference is not implementation
source. No new function-discovery credit or completed component gate is claimed.

## Static evidence

All addresses are ELF virtual addresses, without a runtime rebase or byte masks.
The full capture digest, exact owner-body hashes and unique non-overlapping FDEs
are checked on each reproduction. Complete retained LLVM listings independently
agree with Capstone bytes and instruction boundaries over these owners:

| Start | End exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| `0x4740490` | `0x474120f` | 3,455 | 688 |
| `0x45297f0` | `0x4529ad0` | 736 | 173 |

LLVM renders some LOCK prefixes as separate lines. The verifier joins only
contiguous standalone `f0`/`lock` display prefixes; no bytes are omitted. These
are disassembly denominators, not proof that all owner paths are implemented.

## Frozen comparison and controls

Before Rust existed, `verify.py --prepare` fixed the input and expectation
digests. It refuses preparation if the Rust source exists. The original pre-Rust corpus descriptor is retained in `corpus-before-rust.json`. Only control substitution strings were subsequently refined for formatter/compilation compatibility; the original input and expectation digests are unchanged.

The 7,280 cases cover: Both snapshot states, lookup precedence, exact-zero options, cap-adjacent values, 2^53 conversion boundaries, 2^63/u64 maxima and 2,000 seeded full-width combinations. A second oracle explicitly converts to binary64 and preserves operation order; all 64 output bits are compared without a tolerance.

The independently linked runner gets input words/bytes only, not expectations.
rustc 1.94.1, edition 2021, warnings denied and overflow checks enabled:
debug/optimized/repeated optimized builds each match every row. Own optimized
library digests repeat, own unit tests pass and rustfmt checks pass. Every
separately compiled mutation below completes normally and fails comparison:

| Mutation | Mismatches |
| --- | ---: |
| index_before_map | 4,021 |
| missing_peer_zero | 559 |
| no_snapshot_delay | 6,300 |
| wrong_cap | 170 |
| wrong_factor | 135 |
| integer_product_first | 190 |

`results.json` records compiler identity, corpus/source/harness/verifier hashes,
listing coverage, comparison counts, output and library digests, and controls.
Raw inputs, expectations, compiler/command logs and every runner output remain
in the ignored reproduction output directory and regenerate deterministically.

## Reproduce

```sh
python3 -B research/work-items/RE-012-connect-delay-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/node94-connect-delay-new --controls
python3 -B -m unittest discover -s tests -p test_gossip_connect_stagger_static.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a new output directory. Actual environment: macOS arm64, Python 3.14.5,
Capstone 5.0.7, LLVM disassembler 23.1.4, GNU binutils 2.45 with x86-64 ELF
support, GnuPG 2.5.24, Git LFS 3.8.1 and rustc 1.94.1. All 21 existing
relevant static methods pass without skips. Full validation scope is in
`VALIDATION.md`; hosted CI and independent peer review are not claimed.

## Limits and next work

The API receives normal lookup outcomes and raw u64 X/k words. It does not implement map/list traversal, key equality, snapshot/lock effects, Instant or wall-clock addition, seconds-to-nanoseconds conversion, scheduling, sockets, original ABI, FP exception flags/alternate rounding modes or unwind. Arithmetic is compared in the normal binary64 round-to-nearest domain; no reassociation or integer product is substituted.

No captured binary executes. Only the new host Rust harness/library runs.
No networking, chain action, signing, private runtime state, external dependency,
fake root workspace, stubs, imported-pin changes or progress-gate changes occur.
Static-derived finite comparisons do not establish target execution, original
code identity or integrated-node acceptance. The listed helper/effect gaps
remain next work; full-scope gates stay false.
