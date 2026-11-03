# RE-005: Node115 FeeRateMapSerde MessagePack encoder

- Component: fees / serialization, RE-005; bounded Node115 wire reconstruction under CONTRIBUTING and docs/TASKS.md.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No inferred can1357 source or captured machine code is copied into Rust.
- Status: direct byte/instruction observations, labeled static interpretation and independently authored encoder. No full-scope gate.

## Problem and result

The base tree has no Node115-bound FeeRateMapSerde encoder. A type-name hit alone cannot establish its wire shape. This packet binds the literal to a concrete enclosing writer, follows its direct encoder and finalizer calls, and implements the resulting four-word MessagePack payload in `src/node115-fee-rate-map-codec`. It gives later fee-state reconstruction a buildable encoder with preserved IEEE-754 bits; it does not invent fee units or an integrated node.

All coordinates below are ELF virtual addresses, not raw file offsets or runtime addresses. The four selected complete FDE exports total 2101 bytes of context, not reconstructed/covered bytes or a function census. GNU nearest-export symbols are not recovered names. Raw bytes/operands have no normalization masks.

## Evidence and interpretation

The enclosing writer `0x2764c10..0x2764f54` emits the literal keys `ntl_cutoff`, `rates` and `staking_keep_frac_for_referrer`. At `0x2764d07` / `0x2764d0f` it copies two consecutive 16-byte values to the stack. At `0x2764d19` it loads the exact `FeeRateMapSerde` literal, passes name length 15 and the copied values, and calls `0x2276490`.

The complete encoder `0x2276490..0x2276794` has a special length 10 `_ExtStruct` case. The concrete length 15 caller bypasses it. Both ordinary mode branches write `0x94`. The first three words load at offsets 0, 8, 16, each with a `0xcb` marker and byte swap. The fourth word loads at 24 and calls `0x25e84f0..0x25e8599`: a raw XMM-to-integer move, byte swap and `0xcb` store, with no floating-point arithmetic. These observed stores define a 37-byte array of four binary64 words on the sufficient-capacity, non-aliasing path. The API takes u64 bit patterns to preserve signed zero, infinities and NaN payloads without host numeric conversion.

The finalizer is not silently assumed to do nothing. The writer binds its first state word to `i64::MIN`, then calls `0x22999e0..0x2299b24`. The state load and negation at `0x22999fb..0x2299a04` take the overflow branch directly to `0x2299aa2`: a return-record write and epilogue, with no serializer-buffer write or further call. Other states and allocator/unwind paths remain excluded. The concrete payload is therefore closed without crediting those opaque paths.

`observed/records.json` separates these observations from interpretation and unknowns. `PRE-RUST-FREEZE.json` and `vectors.tsv` preserve 61 expectations frozen before the new Rust source existed. `FREEZE-CLOSURE.json` records the later finalizer closure without changing those expected bytes. The full native exports are retained under `observed/` with their original CRLF bytes. Source/metadata uses LF. The MessagePack format reference is [the official specification](https://github.com/msgpack/msgpack/blob/master/spec.md); the captured instructions, not that reference alone, establish this target's selected format.

## Reproduce

Use the authenticated retained artifact and the repository's required doctor/verify/test/catalogue-check/reproduce commands. For this packet, from the repository root:

```sh
python3 -B research/work-items/RE-005-node115-fee-rate-map-wire/verify.py --rustc /absolute/path/to/rustc-1.95.0 --objdump /absolute/path/to/GNU/objdump --self-test --output work/fee-rate-map-proof
cargo test --locked --offline --manifest-path src/node115-fee-rate-map-codec/Cargo.toml
```

The recorded native Windows build uses Rust 1.95.0 (commit 59807616e, LLVM 22.1.2) and its bundled, archive-authenticated linker. Supply `--linker /absolute/path/to/rust-lld.exe --linker-flavor ld.lld --self-contained` there. The stable spelling avoids the unstable `gnu-lld` spelling; no bootstrap/nightly or default-runtime substitution is used. Cargo uses the same explicit RUSTC/RUSTDOC and RUSTFLAGS. `--linux-lib` additionally builds an x86_64-unknown-linux-gnu rlib when its matching standard-library component is present; it never executes that output. This is a bounded Linux source library, not a node build.

The verifier authenticates the target before tools or output creation, checks actual FDEs, concrete type/call bindings, raw exports and instruction predicates, and re-runs GNU disassembly. It builds the production library and comparison runner in debug, optimized and repeated optimized modes. Each actual runner output must match all 61 pre-frozen rows. No captured code or emulator is run.

## Results and controls

The first full offline/locked Cargo component test passes. The standalone comparison has three matching builds / 183 row comparisons. The four wrong-production implementations (array3, little-endian words, float32 marker and a fourth-word alias) all compile, exit normally and produce detected differences. Six actual-byte counterfactuals below the identity gate are rejected: array marker, word displacement, final float marker, byte swap, finalizer branch and caller name length. A truncated target is rejected before tools/output, and a captured node selected as the compiler is rejected before spawning it.

`comparison-results.json` retains actual commands, explicit production/runner/verifier/vector/record/freeze input hashes, tool hashes, output/library/executable hashes and individual results. Local path prefixes in that metadata alone are labeled placeholders; raw commands/process outputs remain in the local validation record. Compare artifact hashes there rather than inferring binary reproducibility from equal logical output. No target byte-identity match, hosted CI or container result is claimed. Final committed-head repository results belong in the PR, not in a circular self-referencing source claim.

## Limits and next question

This recovers an encoder payload, not a decoder, fee units, positional semantic names, native serializer ABI, allocation/error/unwind behavior, all callers or whole-function/ELF equivalence. It does not advance any component gate or byte-comparison window. Captured node/visor, network, chain and signing operations are not executed. Visor is authenticated only as the repository's retained verification input, not reconstructed.

Original `make verify` on this Windows host fails at MSYS GPG native-path public-key import. That original failure is preserved; it is not changed into a pass. Independently converted public-key/signature arguments authenticate the unchanged retained inputs, and separate original import/packet checks pass. No duplicate of the separate GPG path patch in PR #2340 is included. Any final-head test failure remains explicit in the PR.

Next: recover the decoder's accepted numeric forms, length/errors and consumption rules before implementing a full FeeRateMapSerde round trip or integrating fee-state storage.

The optional `git diff --check` reports trailing spaces in unmodified GNU continuation-byte rows. The raw exports are preserved; no whitespace-check pass is claimed. Independent Rust formatting passes.
