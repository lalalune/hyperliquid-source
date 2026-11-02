# Validation scope

- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- `make doctor verify catalogue-check reproduce`: pass in this checkout. Eight
  artifact identities, three executable signatures, 38 imported files and all
  pinned source repositories match; progress/catalogue remain unchanged.
- 22 existing relevant static methods: pass without skips.
- Own Rust: three 5,800-row debug/optimized/repeated comparisons,
  6 compiled semantic mutants, unit tests and repeated optimized-library
  digests pass. `rustfmt --check` passes. Source/qualifier hashes are recorded.
- Complete shared unchanged inventory: **971/971 files pass**, zero failed files,
  15,468 reported cases, 72 skip records, 1010.982 seconds.
  Six workers run the same fresh-process unittest discovery commands as
  `make test`; only scheduling differs. No test file or assertion is omitted.
  The shared per-file results are retained in [PR #1955](https://github.com/lalalune/hyperliquid-source/pull/1955).
  This branch has its separately executed component/static checks; an
  independent full-suite run on this PR head is not claimed.

`validation-inputs.json` fingerprints the unchanged tracked tools/tests and
registry/provenance/config inputs shared by the three branches. New components
are compiled and compared independently; a shared baseline run is not a separate
full-suite run on every PR head. See README.md for environment and proof limits.
