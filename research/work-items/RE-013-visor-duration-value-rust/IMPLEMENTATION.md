# Qualified duration value implementation

The real dependency-free [visor-duration-value crate](../../../src/visor-duration-value/README.md)
implements `convert_bits(u64) -> DurationValue` for every raw binary64 encoding.
Private fields expose canonical seconds and nanoseconds through getters. The
implementation uses bounded integer arithmetic; the library performs no floating
operations, clock reads, sleeping, process execution or filesystem access.

For positive finite inputs below 2^64, the pair is exact nanoseconds rounded to
nearest, ties to even, then split at one billion. Nonpositive and nonfinite
inputs return zero. At 2^64 the result drops to `(18446744073709, 551615000)`;
large finite inputs keep that pair until raw input `7eb0c6f7a0b5ed8d`, where
million-fold binary64 multiplication overflows and the result returns to zero.
These discontinuities are intentional consequences of the qualified native
branches, not a generic standard-library duration policy.

[PROOF.md](PROOF.md) and [CONTRACT.md](CONTRACT.md) give the conditional native
argument, including SSE2 round-to-nearest-even, masked exceptions, DAZ/FTZ-off,
valid storage, loader/import and ordinary-return premises. The captured code was
never executed or emulated. The complete converter/helper bodies total 658 bytes
and 164 decoded rows; selected caller contexts add 951 bytes and 202 rows. All
captured bytes are credited to prior work, including the fixed-60 analysis in
PR1361. Multiple nonliteral callers motivate this general supplied-value API;
this contribution claims no new byte recovery, generic streaming helper, native
ABI/type/compiler identity or whole-Visor behavior.

## Phase history

The original [README](README.md), pre-code manifest and 61-file
[PRE-RUST-FREEZE.json](PRE-RUST-FREEZE.json) remain unchanged. They record the
state before source existed. The exact Fraction corpus and input-only protocol
were frozen first; separate reviewers independently checked all 59,159 values
before the real crate was authored.

The original [source freeze](rust-validation/SOURCE-FREEZE.json) then bound the
five actual crate files, client, proof and complete build harness. The first
authorized run stopped at command 58: a mutant expression introduced redundant
parentheses rejected by `-Dwarnings`. Production tests and four clean value
streams had passed, but that compiler failure was not a semantic mutant kill.
The original harness, freeze and failed raw receipts remain in
[failed-initial](rust-validation/failed-initial/INITIAL-FAILURE.json).

The [additive amendment](rust-validation/SOURCE-AMENDMENT.json) changes only
that mutant's whole-expression replacement and new-phase admission. Production,
client, corpus, flags and the other 19 mutated source streams are unchanged.
[SOURCE-FREEZE-2.json](rust-validation/SOURCE-FREEZE-2.json) preceded the fresh
successful run. Actual outcomes and byte limitations are in
[VALIDATION-RESULTS.md](VALIDATION-RESULTS.md).

## Reproduce

Run from this packet with the authenticated Visor capture available at the
repository's pinned artifact path and the static tools described in the original
README. Static replay works after source has been added:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B verify.py \
  --scratch /tmp/duration-static-new --receipt /tmp/duration-static-new.json
```

For authored-source qualification, replace the toolchain placeholder with the
installed Rust 1.94.1 aarch64-apple-darwin payload matching TOOLCHAIN-PINS.json.
Use a fresh direct child of canonical `/tmp` and a fresh private-map path outside
the packet. The harness audits actual source, Cargo metadata, lockfile, hooks,
ancestor configs/workspaces, toolchain and selected linker/SDK inputs before
building. It uses offline/locked Cargo and no network dependencies.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B rust-validation/build-amended.py \
  --toolchain /path/to/pinned/toolchain \
  --out /tmp/duration-author-new \
  --private-map /tmp/duration-author-new-private-map.json \
  --source-freeze-sha 124103cce3fa160760b833630ef47a51d56f7a24edc3a3cca51bb11175a5d5d9
```

The original `build.py` is historical; use `build-amended.py`. Expected values
are read only by the comparison harness. The Rust client receives opaque IDs and
raw input bits and emits its own values. A build executes only the authored Rust
crate/client and declared host tools, never the captured executable.
