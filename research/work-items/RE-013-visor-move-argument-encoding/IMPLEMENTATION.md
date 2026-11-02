# Combined six-body proof and Rust value reconstruction

This is the implementation phase of the same contribution, not a second recovery or an additional byte-credit claim. The original [README](README.md), [PROOF](PROOF.md), `MANIFEST.json` and `AUTHOR-FREEZE.json` retain their earlier static-phase bytes. [The real Rust component](../../../src/visor-move-request/README.md) implements the proved move-request **byte values** for canonical UTF-8 inputs after externally admitting the opaque preflight.

The pure API omits empty/all-W arguments, preserves every original byte of retained arguments, applies the exact native byte-mask/chunk grammar, joins `mv`, source and destination with single ASCII spaces, rejects embedded NUL, and exposes raw option byte **1**. It has no subprocess, shell, filesystem, network or preflight interface. New safe types, host allocation errors and length-domain refusals are explicitly chosen APIs rather than inferred native layouts. Option 1 does not guarantee quiet wrapping, and no actual move effect or generic escaping-safety claim is made.

The [pre-Rust contract](pre-rust/CONTRACT.md), independent longest-prefix-per-language oracle and frozen 44,679-pair/211-length corpus preceded production source. The [code bridge](rust-validation/BRIDGE.md) connects the safe implementation to the conditional native relation. [Rust validation](rust-validation/VALIDATION.md) documents the pinned real Cargo builds, input-only linked client, complete raw comparisons, compiled semantic mutants and precise limitations.

The chronological integrity records are separate:

1. `MANIFEST.json` and `AUTHOR-FREEZE.json`: original six-body static phase.
2. `pre-rust/PRE-RUST-FREEZE.json`: contract, independent oracle and expected corpus, before production Rust existed; root independently admitted this gate.
3. `rust-validation/SOURCE-FREEZE.json`: actual source, input client, build driver and bridge before the first production compilation.
4. `IMPLEMENTATION-MANIFEST.json` and `IMPLEMENTATION-FREEZE.json`: final combined retained artifact identities after actual validation, without rewriting the earlier freezes.

The earlier native denominator remains six complete FDEs, 4,067 bytes and 1,007 rows, plus 137 explicitly selected context bytes. No new compiled-target match, original allocator/ABI reconstruction, preflight predicate, shell behavior, actual filesystem effect or full component gate follows from this Rust phase. The separate preparation-policy work in PR 1437 and node-94 shell-route work in PR 1464 are not dependencies or duplicate scope.
