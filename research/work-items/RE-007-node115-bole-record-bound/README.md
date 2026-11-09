# Node #115 BOLE record bound and caller handoff

Backlog HL115-100; a partial constructor contract, not a complete BOLE operation.
Target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Addresses are original ELF virtual addresses. No captured execution or emulation.

## Prior work and remaining scope

PR #2937 covers the selector prefix at `0x2c80670`, and #2274 its lookup/counter
behavior. Open #5071 covers scale helper `0x434f580`; this packet credits that
helper and does not duplicate its implementation or run its instruction evaluator.
The new result follows the selected call into constructor `0x449bd50`, proves a
numeric refusal unreachable under this caller's invariant, and maps the explicitly
written record fields back to the caller. Later asynchronous execution remains open.

## Observation and proof

After the credited selection/lookup, `0x2c808ab` compares converted R8 against one;
`0x2c808af` adds the carry bit. Exactly zero becomes one; every nonzero u64,
including u64::MAX, is preserved. No intervening instruction writes R8 before
`0x2c809b1`, whose relocation `0x64e7f30` resolves to `0x449bd50`.
The prior float conversion is not reconstructed here: this invariant is valid for
any u64 present at the compare.

The constructor validates the selected metadata index, obtains the first qword of
its 32-byte row, and calls `0x64e4ef0 -> 0x434f580` with the caller's R9 input.
Let its successful u64 result be `s`, and let the nonzero factor be `f`.
At `0x449bd98..0x449bdb4`, the constructor computes:

```
c = min(s, floor(1_000_000_000_000_000_000 / f))
p = c * f
```

Thus `p <= 10^18 < 2^63-2`, for every u64 `s` and every `f >= 1`. The following
multiplication-overflow or `p > 2^63-2` refusal at `0x449bdd3` cannot be taken on
this selected caller path. This is an algebraic consequence of observed unsigned
min/divide/multiply instructions, not a claim based only on test samples. Invalid
indices, helper failure/unwind, earlier refusal and other callers are not excluded.
In particular it does not prove successful end-to-end BOLE processing.

## Record and consumer

Successful construction copies an opaque 0x250-byte prefix and writes:

| Offset | Written value |
| --- | --- |
| +0x250 | factor f, u64 |
| +0x258 | selected metadata index, u64 |
| +0x260 | capped result c, u64 |
| +0x268 | product p, u64 |
| +0x270 | zero, u64 |
| +0x278 | caller's 12-byte stamp |
| +0x284 | low byte of constructor flag |

The selected caller passes flag one. After construction, it copies the first
0x270 bytes and the 16-byte tail starting +0x278, then **overwrites +0x270** with
the saved lookup object's +0x10 qword (`0x2c807ec` -> stack -> `0x2c80a17`).
Consequently the constructor's zero is not the caller's final field value. Neither
field is assigned an unsupported economic or state-machine name here. The three
padding bytes after +0x284 are copied by the native caller but are unspecified.

The owned Rust crate computes the bound, writes the explicitly initialized bytes,
and composes the caller replacement. Its supplied prefix is opaque initialized
storage, not an assertion about every native prefix/padding byte. Supplying the
helper result as a quantified input does not stand in for the missing scale helper.
The downstream consumer can use the cap and exact field handoff while retaining
that helper and the later operation as explicit prerequisites.

## Reproduction and limits

```
python3 research/work-items/RE-007-node115-bole-record-bound/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-bole-record-bound/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-bole-record-bound/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-bole-record-bound/Cargo.toml
cargo +1.95.0 clippy --manifest-path src/node115-bole-record-bound/Cargo.toml --all-targets -- -D warnings
```

Five tests pass in both profiles, including 4096 deterministic cases against an
independent u128 product-first oracle, zero/max factors, cap rounding, exact field
writes and caller replacement. Formatting and Clippy pass with Rust 1.95.0.
Static verification with Python/Capstone 5.0.7 authenticates the complete target,
two FDEs, 1443 selected bytes, 310 instructions and 318 facts. All 18 semantic
corruptions are rejected, including factor floor, cap, min direction, threshold,
relocations, record fields and final overwrite; rejection is checked beyond the
whole-file/window digest guards after authenticating the original target.

Repository check results are in the PR. Allocation, unwind, helper internals,
physical prefix ownership, the original floating calculation and asynchronous
operation remain open. All component gates remain false. New source and evidence
are independently authored under MIT; no unlicensed inferred source was copied.
