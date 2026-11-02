# Validation scope

- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- `make doctor verify catalogue-check reproduce`: pass in this checkout. Eight
  artifact identities, three executable signatures, 38 imported files and all
  pinned source repositories match; progress/catalogue remain unchanged.
- 22 existing relevant static methods: pass without skips.
- Own Rust: three 5,800-row debug/optimized/repeated comparisons,
  6 compiled semantic mutants, unit tests and repeated optimized-library
  digests pass. `rustfmt --check` passes. Source/qualifier hashes are recorded.
- A fresh full 971-file inventory is running in one shared checkout; this
  revision does not claim that pending run passed.

`validation-inputs.json` fingerprints the unchanged tracked tools/tests and
registry/provenance/config inputs shared by the three branches. New components
are compiled and compared independently; a shared baseline run is not a separate
full-suite run on every PR head. See README.md for environment and proof limits.
