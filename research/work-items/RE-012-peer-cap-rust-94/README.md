# RE-012 / node-runtime: node94-peer-cap

## Gap and recovered scope

The baseline has static evidence for the flagged gossip peer-cap path, but no independent Rust implementation. This adds the option-to-limit rule, supplied-peer IPv4 projection, exempt-peer counting and intermediate result code. None defaults to 8; Some(v) clamps to [8,100] and requests a clipping diagnostic only if changed. Bit-0-tagged keys map to 127.0.0.1. Allowed IPv4 entries are excluded from the count; at exact capacity only an allowed incoming key gets code 3.

Base main: `e5c9b6436876b2a4a39daef813171f9879317699`. Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The existing project-authored producer `tools/gossip_peer_cap_static.py` supplies maintained
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
| `0x473f2e0` | `0x4740482` | 4,514 | 921 |

LLVM renders some LOCK prefixes as separate lines. The verifier joins only
contiguous standalone `f0`/`lock` display prefixes; no bytes are omitted. These
are disassembly denominators, not proof that all owner paths are implemented.

## Frozen comparison and controls

Before Rust existed, `verify.py --prepare` fixed the input and expectation
digests. It refuses preparation if the Rust source exists.

The 5,800 cases cover: Exhaustive selected option/limit/peer-count boundaries (including 7/8/9 and 99/100/101), raw tag bits, localhost projection, allowed-set combinations and 1,000 seeded full-width scenarios. An independent canonical-key/count formulation cross-checks the maintained static model.

The independently linked runner gets input words/bytes only, not expectations.
rustc 1.94.1, edition 2021, warnings denied and overflow checks enabled:
debug/optimized/repeated optimized builds each match every row. Own optimized
library digests repeat, own unit tests pass and rustfmt checks pass. Every
separately compiled mutation below completes normally and fails comparison:

| Mutation | Mismatches |
| --- | ---: |
| wrong_minimum | 1,460 |
| wrong_default | 828 |
| wrong_local_tag | 1,875 |
| count_allowed_peers | 4,764 |
| inclusive_capacity | 332 |
| invert_allowlist_bypass | 2,154 |

`results.json` records compiler identity, corpus/source/harness/verifier hashes,
listing coverage, comparison counts, output and library digests, and controls.
Raw inputs, expectations, compiler/command logs and every runner output remain
in the ignored reproduction output directory and regenerate deterministically.

## Reproduce

```sh
python3 -B research/work-items/RE-012-peer-cap-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/node94-peer-cap-new --controls
python3 -B -m unittest discover -s tests -p test_gossip_peer_cap_static.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a new output directory. Actual environment: macOS arm64, Python 3.14.5,
Capstone 5.0.7, LLVM disassembler 23.1.4, GNU binutils 2.45 with x86-64 ELF
support, GnuPG 2.5.24, Git LFS 3.8.1 and rustc 1.94.1. All 22 existing
relevant static methods pass without skips. Full validation scope is in
`VALIDATION.md`; hosted CI and independent peer review are not claimed.

## Limits and next work

Code 3 is an intermediate cap result: the native owner has a further unresolved step and this API does not establish final peer admission. Original option/NodeIp layout, B-tree iteration/equality/helper bodies, tracker loading, locks, logs, mutation order, ownership/unwind and concurrent effects remain unclosed. The supplied vector/slice API is new; synthetic vectors are not a proof of original map reachability.

No captured binary executes. Only the new host Rust harness/library runs.
No networking, chain action, signing, private runtime state, external dependency,
fake root workspace, stubs, imported-pin changes or progress-gate changes occur.
Static-derived finite comparisons do not establish target execution, original
code identity or integrated-node acceptance. The listed helper/effect gaps
remain next work; full-scope gates stay false.
