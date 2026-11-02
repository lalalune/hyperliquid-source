# RE-001 / foundation: node94-restart-settings

## Gap and recovered scope

The baseline has static evidence for restart-setting codec selection and normal return words, but no independent Rust implementation. This adds the final-component classifier, supplied-helper result projection and unsigned page-count floor. A nonleading final dot and exactly three ASCII-case-insensitive rmp bytes select the binary candidate. Binary success is low byte 9; text success is low bit zero. Ineligibility or the exact 2^63 read-error word produces zero; the wrapper maps zero to one and preserves all nonzero u64 values.

Base main: `e5c9b6436876b2a4a39daef813171f9879317699`. Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The existing project-authored producer `tools/restart_setting_static.py` supplies maintained
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
| `0x13ca000` | `0x13ca0d5` | 213 | 53 |
| `0x144b900` | `0x144bfcb` | 1,739 | 370 |

LLVM renders some LOCK prefixes as separate lines. The verifier joins only
contiguous standalone `f0`/`lock` display prefixes; no bytes are omitted. These
are disassembly denominators, not proof that all owner paths are implemented.

## Frozen comparison and controls

Before Rust existed, `verify.py --prepare` fixed the input and expectation
digests. It refuses preparation if the Rust source exists. The original pre-Rust corpus descriptor is retained in `corpus-before-rust.json`. Only control substitution strings were subsequently refined for formatter/compilation compatibility; the original input and expectation digests are unchanged.

The 28,780 cases cover: 18 component forms, all eight RMP ASCII-case variants, absent/ineligible/read-error cases, signed/high-bit/full-width words, and all 256 parser low bytes with three high-word patterns. The maintained byte-bound model is checked against a separate suffix and truth-table oracle.

The independently linked runner gets input words/bytes only, not expectations.
rustc 1.94.1, edition 2021, warnings denied and overflow checks enabled:
debug/optimized/repeated optimized builds each match every row. Own optimized
library digests repeat, own unit tests pass and rustfmt checks pass. Every
separately compiled mutation below completes normally and fails comparison:

| Mutation | Mismatches |
| --- | ---: |
| leading_dot_extension | 1,517 |
| case_sensitive_extension | 12,107 |
| binary_success_low_bit | 4,761 |
| text_success_full_word | 2,277 |
| wrong_read_sentinel | 736 |
| invert_eligibility | 6,471 |
| wrong_zero_wrapper | 25,715 |

`results.json` records compiler identity, corpus/source/harness/verifier hashes,
listing coverage, comparison counts, output and library digests, and controls.
Raw inputs, expectations, compiler/command logs and every runner output remain
in the ignored reproduction output directory and regenerate deterministically.

## Reproduce

```sh
python3 -B research/work-items/RE-001-restart-settings-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/node94-restart-settings-new --controls
python3 -B -m unittest discover -s tests -p test_restart_setting_static.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a new output directory. Actual environment: macOS arm64, Python 3.14.5,
Capstone 5.0.7, LLVM disassembler 23.1.4, GNU binutils 2.45 with x86-64 ELF
support, GnuPG 2.5.24, Git LFS 3.8.1 and rustc 1.94.1. All 6 existing
relevant static methods pass without skips. Full validation scope is in
`VALIDATION.md`; hosted CI and independent peer review are not claimed.

## Limits and next work

The input is a supplied final component, not a full path. Actual path expansion/predicate, file reads, JSON/messagepack grammars, concrete native types, global root state, diagnostics, allocation/drop/unwind and original ABI remain unclosed. Synthetic component/helper-word combinations need not be reachable from the original caller.

No captured binary executes. Only the new host Rust harness/library runs.
No networking, chain action, signing, private runtime state, external dependency,
fake root workspace, stubs, imported-pin changes or progress-gate changes occur.
Static-derived finite comparisons do not establish target execution, original
code identity or integrated-node acceptance. The listed helper/effect gaps
remain next work; full-scope gates stay false.
