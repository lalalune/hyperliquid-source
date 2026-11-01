# Implemented child-argument owned values

The real dependency-free component [src/visor-child-args](../../../src/visor-child-args/README.md) now implements the qualified byte-value relation: collect canonical UTF-8 spans in order until the first null-empty descriptor, retain nonnull empty arguments, and copy every admitted byte including NUL. Returned Strings own their storage. Invalid UTF-8, host allocation failure and an out-of-domain descriptor count are explicit safe API refusals, not recovered native error objects.

This implements the pre-code [contract](CONTRACT.md) and [conditional bridge](BRIDGE.md). The three complete value bodies are credited to #1029/#1040 (1430 B / 378 rows); the selected #988 caller corridor contributes context, not a new whole-extractor theorem or byte-coverage credit. Binding covers four full FDEs, 1996 B / 503 rows, real CIE/FDE records, seven used relocation slots and the lead-width table. The caller's selected `child-args` copy endpoint ends before its opaque cleanup. No whole-Visor completion gate changes.

## Actual qualification

| Check | Author observation |
| --- | --- |
| Actual offline/locked build | Rust 1.94.1, aarch64-apple-darwin; real Cargo metadata shows one dependency-free lib/test package |
| Focused tests | 8 passed in debug and 8 in release |
| Input-only client | 108,604 collection cases and 197 integer cases exactly equal the pre-code expected streams in both profiles |
| Separate clean directory | Both profiles again match both streams |
| Compiled wrong implementations | All 14 compile and differ from the frozen oracle in both profiles |
| Comparator corruptions | All 12 rejected by exact-byte comparison |
| Post-source native/grammar replay | All 12 generated files byte-identical to their immutable pre-code versions |
| Captured target execution | None; no captured instruction evaluator |

The 146 recorded subprocess commands and all raw stdout/stderr are in [receipts/commands.json](rust-validation/receipts/commands.json). The 292 stream references resolve to 67 unique content-addressed gzip streams, rehashed after copying the actual build output. [results.json](rust-validation/receipts/results.json) records complete comparisons and mutant counts; [AUTHOR-RUN.json](rust-validation/AUTHOR-RUN.json) records the outer command, retained-copy check and logical/private mapping. Expectations and semantic category labels are separate from the input-only driver. Invalid-input comparisons exercise the chosen safe refusal, not the opaque native error path.

The mutations cover continuing or manufacturing an element at None, stopping at or dropping an empty argument, rejecting or truncating NUL, lossy decoding, trimming, reversing, removing duplicates, returning the previous error index, rejecting the largest admitted descriptor count, wrapping multiplication and using the wrong descriptor stride. Each counted mutant produces its own library/client output; compiler failure is not a passing sensitivity result.

Own clean-build rlibs are raw-equal in both profiles, and release clients are raw-equal. Debug clients are **not** raw-equal and contain their canonical build prefixes despite compiler remapping; this difference is retained. No masks, normalization, cosmetic retry or comparison to captured machine code is used. These host-build observations do not establish original compiler, native layout or binary identity.

## Preserved chronology and correction

The original 23-file pre-code manifest and PRE-RUST-FREEZE.json remain unchanged. Their source-absence observation predates the authorized implementation; the historical verify_precode.py deliberately cannot run unchanged after source exists. The usable replay below invokes the frozen binder and oracle directly and admits the earlier receipt as historical evidence only.

The initial source freeze is [SOURCE-FREEZE.json](rust-validation/SOURCE-FREEZE.json), SHA-256 `008542842de569e0af3301e542aae9b360e79d0b6bdf9382ba554adf13a417ef`. Its first library build passed, then the first debug test compilation failed with E0308: `[Some(b""); 7]` retained the array-reference element type. The corrected test writes `[Some(&b""[..]); 7]`. No production library or expected output changed.

The original freeze, build.py, verify.py and seven harness files remain byte-identical at their original paths. [amendment-1](rust-validation/amendment-1/README.md) retains the exact initial test/README, all 15 failed-attempt command records/raw streams, and precise diffs. The source README now names the distinct amended entrypoints. The amended harness changes only the selected freeze and replay module identity. Its [SOURCE-FREEZE-2.json](rust-validation/SOURCE-FREEZE-2.json), SHA-256 `ae8116f89b316e3137fde905b08c37854b95b09b3ff8d934deeef69db0fcaa16`, was fixed before the retry. There were no later source/harness changes during qualification.

## Reproduce from the final checkout

Use the complete authenticated capture and credited evidence at their repository paths. Output directories must be fresh. The static command works with source present:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-013-visor-child-args-rust/rust-validation/verify_amended.py --out /tmp/child-args-replay-UNIQUE --source-freeze-sha ae8116f89b316e3137fde905b08c37854b95b09b3ff8d934deeef69db0fcaa16
```

For the complete actual build, supply the installed directory matching the 97 bin/lib file hashes and symlink inventory in TOOLCHAIN-PINS.json. The private map must be a fresh path outside this packet. It records local paths; public metadata uses `<BUILD>`, `<TOOLCHAIN>`, `<SOURCE>` and `<PACKET>`. Raw tool streams retain ordinary temporary build paths without redaction; no user-home path was admitted in them.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-013-visor-child-args-rust/rust-validation/build_amended.py --toolchain PATH_TO_PINNED_1_94_1_TOOLCHAIN --out /tmp/child-args-build-UNIQUE --private-map /tmp/child-args-private-map-UNIQUE.json --source-freeze-sha ae8116f89b316e3137fde905b08c37854b95b09b3ff8d934deeef69db0fcaa16
```

The harness admits frozen source/client/harness bytes, exact real Cargo graph/lock, no build script or dependencies, copied-source identity, fresh Cargo home, lexical and canonical ancestor config absence, toolchain payload/link identities, explicit environment and selected linker/SDK bytes. It uses offline/locked builds and retains source/tool identity checks after execution. The source library contains no process, filesystem, environment, socket or target interface. The host OS/dyld and entire SDK are not hermetically pinned.

## Remaining limits

Native valid-span, nonaliasing, frame, finite ordinary callback, allocator and exact-copy premises remain explicit in BRIDGE.md. The native allocator, libc implementation/interposition, invalid-UTF8 helper, cleanup/unwind and upstream table-search behavior remain opaque. Growth is excluded by the proved native count/capacity domain; it is not reimplemented. The safe count helper is a chosen admission of that domain, not a recovered native standalone function.

No native container/descriptor/error ABI, allocator order/capacity, OOM behavior, process argv, public CLI policy, execution through the caller's later cleanup, 32-bit behavior or full module recovery is claimed. The mathematical oracle's canonical scalar construction is independent of the Rust validity decoder; its target grounding is the reviewed static bridge, not observed target execution. Official standard-library documentation supplies only an API premise. Native helper closure or later caller behavior requires a separate bounded investigation.
