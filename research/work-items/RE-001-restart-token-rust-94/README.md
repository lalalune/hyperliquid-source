# RE-001 / foundation: independent restart ASCII-token Rust projection

## Question, scope and provenance

The baseline has static evidence for the post-replacement restart token
pipeline, but no Rust component at `src/node94-restart-token/`. This packet
adds that bounded implementation and an independently linked scalar harness.
It does not claim a newly discovered function or a completed component gate.

- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: node94 `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Existing project-authored evidence/model: `tools/restart_token_filter.py`
  and `research/work-items/RE-001-restart-token-filter-94/`.
- The original unlicensed reference remains a lead, not implementation source.
  The new Rust was authored from the authenticated observations. No reference
  Rust, captured executable code or proprietary runtime data is copied into it.

## Target observations and implementation

Addresses are ELF virtual addresses, without rebasing or operand masks.
`evidence.json` authenticates the complete input and binds the maintained
tool hash, fresh static output, unique non-overlapping owner FDEs and complete
owner-body hashes. Complete LLVM listings cover:

| Owner | End exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| `0x1438e90` | `0x143900c` | 380 | 88 |
| `0x13df3c0` | `0x13df5ed` | 557 | 145 |
| `0x13df5f0` | `0x13df766` | 374 | 97 |
| `0x14b1090` | `0x14b14b3` | 1,059 | 265 |

Capstone and LLVM independently agree on all 2,370 captured bytes and 595
instruction boundaries. That is a disassembly denominator, not a claim to
implement every path in those owners.

The existing byte/data checks establish separator mask `0x100003e00` at
`0x13df3ef`, exact 13-byte token comparison through overlapping loads at
`0x13df5b5..0x13df5d3`, and the caller's one-byte join length. Its rodata
pointer addresses a longer ` --backup-logs` string, but only the first space
is the separator. The Rust implements the established ASCII projection:

1. Split on bytes 9, 10, 11, 12, 13 and 32; discard empty tokens.
2. Discard precisely the token `--backup-logs`, including repeated instances.
3. Join surviving tokens with a single ASCII space.

Quotes, embedded NUL and lookalike flags remain literal token bytes. Non-ASCII
input returns `None`, a new safe API refusal. It is not an inferred native
Unicode outcome. The input is the replacement helper's returned buffer;
the original command's contains/replacement helpers are not implemented.

## Comparison protocol and controls

`verify.py --prepare` fixed `corpus.json` and `evidence.json` before the Rust
source existed; it refuses preparation if the source is present. `cases.py`
extracts mask, skipped token and joiner from the authenticated image. A separate
translate/split/join oracle agrees with the maintained static model.

The frozen 21,233 cases include all 128×128 ASCII flanks around a backup flag,
all 13×256 single-byte token replacements, every single-byte input and its
space-delimited form, quoted/lookalike/NUL/empty/repeated cases, and 1,000
seeded token sequences. Of these, 1,920 exercise only the new non-ASCII refusal;
the other 19,313 exercise the established conditional ASCII projection. Some
synthetic buffers may be unreachable from the original caller.

The runner receives inputs only. rustc 1.94.1, edition 2021, warnings denied,
overflow checks enabled: debug, optimized and repeated optimized libraries
each match all rows. The two optimized library hashes agree. Three own Rust
unit tests pass. The five separately compiled mutations finish normally and
are rejected by output mismatches:

| Mutation | Mismatches |
| --- | ---: |
| Keep the removed flag | 603 |
| Retain empty split segments | 1,048 |
| Omit vertical-tab separator | 874 |
| Join with tab | 2,405 |
| Admit non-ASCII | 1,920 |

`results.json` records compiler identity, generator/input/expectation/source/
harness/verifier hashes, decoder coverage, comparisons and mutation results.
Raw inputs, expectations, process outputs and compiler/command logs remain in
the chosen ignored output directory and can be regenerated exactly.

## Reproduce and boundaries

With authentic pinned inputs, Python 3 with Capstone 5.0.7 and rustc 1.94.1:

```sh
python3 -B research/work-items/RE-001-restart-token-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/restart-new --controls
python3 -B -m unittest discover -s tests -p test_restart_token_filter.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a new output directory. Preparation is historical; ordinary reproduction
checks the committed corpus and evidence and does not overwrite them.
The existing six target-evidence tests pass without skips. Repository-wide
validation is recorded separately in `VALIDATION.md`.

No captured binary is executed. The new output-vector API uses the host Rust
allocator, with no original allocation, lifetime, drop, unwind, fault, Unicode,
shell, process, whole-function or whole-ELF claim. There are no new external
dependencies, root workspace, binary-comparison windows or progress updates.
The next semantic gap is the upstream replacement and Unicode paths.
