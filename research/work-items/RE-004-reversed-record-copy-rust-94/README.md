# Node #94 ordered reversed-record copy in safe Rust

This packet adds the previously unimplemented Rust value component for
`[0x3818d40, 0x3818dc4)`, a complete 132-byte leaf with 31 instructions. It extends
the static findings in
[`foundation-simd-byte-reversed-copy-94`](../foundation-simd-byte-reversed-copy-94/README.md)
to all overlap layouts through a safe single-arena API. The original foundation
packet, tools, tests, registry, pinned artifacts and progress gates are unchanged.

[`lib.rs`](../../../src/node94-reversed-record-copy/lib.rs) preserves the four
ordered block loads/stores and returns a destination-offset projection of full
RAX. Invalid or overflowing ranges are refused before mutation. The new `None`
result is not attributed to the original pointer ABI. The
[proof](PROOF.md) covers all byte values, block snapshot order, aliasing, bounds
and termination; its normal-return memory premises and exclusions are explicit.

Fresh full-body GNU/LLVM exports and `static.json` bind the leaf, neighboring
FDEs/padding, two complete caller bodies and four aligned indirect calls. The
newly resolved `.got` slot `0x5775570` contains zero file bytes and is bound by
an `R_X86_64_RELATIVE` addend to `0x3818d40`. There are no direct E8 candidates;
the four FF15 calls occur in callers `0x326b090` and `0x3284c70`. This does not
claim an exhaustive indirect reference census or identify an original type,
library or application purpose. All 24 structural corruption controls fail
below the top-level target hash check.

## Frozen expectations and native qualification

Before creating Rust source, `oracle.py` froze a mathematical byte-preimage
composition oracle, rather than simulating loads/stores. `frozen.json` binds the
target, static evidence, oracle, compressed input/expected streams and 107
canonical provenance maps. It records 3,022 cases: 2,837 admitted, including
2,332 overlapping, and 185 refused without mutation. Coverage includes every
overlap displacement `-51..51`, touching/disjoint ranges, all 16 source alignment
phases, every constant byte value, one-hot bytes, exact/short bounds, huge offsets
and digest-derived layouts. The 256-byte backing arena is a harness fixture
limit, not a limit imposed by the library.

The exact installed rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`, compiled and
ran the new library and input-only client at opt-level 0 and 3 on
`aarch64-apple-darwin`. Both profiles matched all 3,022 frozen records and passed
three unit tests. Each profile's repeated rlib and client were raw-byte identical,
four comparisons total; no normalization was used. Overflow checks remained on.

Eleven wrong implementations were compiled and run normally in each profile:

| Wrong implementation | Mismatching cases per profile |
| --- | ---: |
| Snapshot entire source before all writes | 1,473 |
| Read/write one live byte at a time | 1,451 |
| Reverse each eight-byte half | 2,449 |
| Omit first reversal | 2,365 |
| Swap first two stages | 749 |
| Wrong dword destination offset | 2,309 |
| Wrong vector source offset | 2,371 |
| Swap reversed destination fields | 2,461 |
| Return source offset | 2,749 |
| Reject exact-fit source range | 21 |
| Clamp packed bytes to 127 | 1,357 |

All three order/snapshot controls have actual memory mismatches on admitted
overlapping cases. Detailed first differing bytes and separate return/memory
counts are retained in `native/results.json`. Framing, missing/changed output,
oversized harness storage and unknown fixture patterns are also checked.

`native/calls.json` records command argv, exit status, stdin digest and both raw
stream hashes for each call. `native/raw-streams.json.gz` stores those streams
losslessly, with duplicate payloads stored once. `checks.json` and `checks/`
retain focused/global checks and the honest initial verifier failure: a mutation
selector also matched a doc comment. The selector was narrowed, all selectors
were moved into preflight, and the complete qualification was rerun in a fresh
directory without changing Rust source or frozen expectations.

## Replay

Run from the repository root with verified pinned inputs. The native command
requires the exact compiler executable above and a fresh output directory:

```sh
python3 -B research/work-items/RE-004-reversed-record-copy-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-reversed-record-copy-rust-94/verify_rust.py \
  --rustc "$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)" \
  --out work/reversed-record-copy-rust/replay
```

The actual recorded qualification used normal Python; independent static replay
also passed under `python3 -O`, changed hash seeds and time zones. `--freeze`
commands deliberately refuse to overwrite evidence or freeze after Rust exists.
`SHA256SUMS` binds the new source/evidence plus the unchanged focused legacy tool
and test. Gzip fixtures and streams must be materialized through Git LFS.

Local validation passed `make doctor`, `make verify`, `make catalogue-check`,
`make reproduce`, all 10 focused legacy tests and the legacy evidence replay.
No full-suite or hosted-CI result is claimed here. No captured binary or captured
instruction emulator ran; no unlicensed inferred source was read or copied.
The contribution is independently authored OpenAI/Codex work; the exact model
identifier was not available. Compiled-byte identity with the target, original
build provenance and whole-node equivalence remain unclaimed.
