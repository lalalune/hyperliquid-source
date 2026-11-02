# RE-008: selector-0 block preimage

This packet reconstructs the block preimage that the existing consensus component leaves behind its authentication interface. The conditional value contract includes ordered transaction hashes, packed time, all QC vote signatures and optional TC rows. A nested timeout row emits its signature before its body. Packed time becomes signed Unix seconds through calendar arithmetic, zigzag-encoded, followed by the unchanged u32 nanoseconds word; it is not a millisecond clamp.

Review [PROOF.md](PROOF.md) first, then the independently derived [corpus](corpus.py), original [source plan](SOURCE-PLAN.md) and [input-only protocol](PROTOCOL.md). The real [consensus crate](../../../src/node94-consensus-admission/src/block_preimage.rs) now supplies checked length, preimage and digest APIs with explicit `PackedBlockTime`. [IMPLEMENTATION.md](IMPLEMENTATION.md) maps the value contract into source. The immutable pre-code freeze retains its original chronology.

- Target: node94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Source baseline: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Native scope: 32 complete FDEs, 14,506 bytes and 3,560 instructions, including full signer/verifier callers, paired block/time/TC/QC/signature serializers and sizers, dispatcher, concatenation and hash wrappers.
- Expectations: 1,141 value cases, 91–16,663 preimage bytes, nine 136-byte hash-rate boundary witnesses. The independent integer certificate covers all 524,288 packed years and both ordinal endpoints.
- Evidence controls: 83 rejected changes, including 64 fresh GNU/LLVM decodes of modified full function bodies below the target/body identity gates. These test evidence admission and structural obligations; they are not executed semantic mutants or a substitute for the manual proof.
- Own Rust: debug/release and both clean same-path rebuilds each match all1,141 frozen cases. Each profile passes36 library and7 new integration tests. All17 compiling source mutants are detected in both profiles; [actual results](rust-validation/VALIDATION.md) retain all126 command outcomes.

The result assumes stable valid native source objects, truthful finite counts, nonwrapping spans, disjoint output/scratch, successful allocation, ordinary return, explicit opaque-call preservation and the imported memcpy copy/frame contract. Body length plus the 29-byte domain prefix must be below 2^63. All raw time words are admitted without a calendar-validity claim. Keccak permutation identity remains conditional on the credited baseline structural identification. Signature validity, recovery, native ownership, malformed memory, unwinding and full authenticator integration remain open.

## Reproduce the static evidence

From the repository root with the exact captured artifact already present:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-block-preimage-94/verify.py --out /tmp/block-preimage-check
PYTHONDONTWRITEBYTECODE=1 python3 -O research/work-items/RE-008-block-preimage-94/verify.py --out /tmp/block-preimage-check-opt
```

Output directories must be new. Optional `--binary`, `--gnu` and `--llvm` select the artifact and native providers. Recorded provider identities/options are in [native-providers.json](native-providers.json). Native text is version-sensitive; reproduction with different providers may require reviewing textual differences, and the verifier deliberately does not silently bless them. Each invocation validates the immutable pre-code receipt, reproduces native exports and mathematical fixtures in two fresh trees, compares them with the retained bytes and runs admission controls. It never executes captured instructions.

The exporter reads one SHA-admitted private input snapshot for both native tools. Full GNU text is directly readable; equivalent LLVM byte partitions and large fixtures use deterministic gzip stored as ordinary Git blobs by the local `.gitattributes`. [records.json](records.json) retains exact extents, FDE/CIE bytes, source offsets, call census and raw relocation records. Its compact format avoids duplicating full instruction text. [scope.json](scope.json) and [obligations.json](obligations.json) define the exact evidence boundary. [VALIDATION.md](VALIDATION.md) distinguishes actual checks from planned source work.

The baseline block proposal/admission packets explicitly stub the digest and provide layout/caller context, not expected digest values. Related selector-1 PR1391, selectors2–4 PR1467, concurrent timeout projection PR1444 and packed-date-add PR1473 are credited in [OVERLAP.md](OVERLAP.md); none is a runtime dependency. Baseline ELF/FDE parsers, scalar codec and independently authored Keccak dependencies are hash-pinned in [dependencies.json](dependencies.json). No unlicensed reference source was copied.

## Reproduce the authored Rust checks

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-block-preimage-94/build.py --toolchain-bin /path/to/rust-1.94.1/bin --out /tmp/block-preimage-rust-check
```

The output directory must be new. Omitting `--toolchain-bin` uses the recorded
macOS research toolchain location. This validates both freezes, copies the actual
three-package Cargo graph, builds offline/locked, runs the input-only client and
compiling mutants, and preserves raw streams. It runs only independently
authored host code, not the captured executable. Full authenticator integration
and native cryptographic validity remain outside this contribution.
