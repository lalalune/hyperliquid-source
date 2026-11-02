# Validation scope

- All-feature Rust tests pass in debug and release: 152 tests each, including
  five hash-helper tests. Thirteen frozen cases compare full record encodings
  and digests against a separately run Python MessagePack encoder and BLAKE3
  binding. The binding may share upstream BLAKE3 code with the Rust dependency;
  this is not independent-algorithm or captured-target differential validation.
  Explicit integer fixtures cover 169 pairs of boundary values.
- Linux x86-64 all-feature release library build passes. This produces an rlib;
  it is not a node executable or a Linux runtime acceptance result.
- Clippy with all targets/features and warnings denied, and rustfmt, pass.
- Nine incorrect Rust implementations compile and fail the independent fixture
  test: outer/inner array encoding, wrong key, swapped counters, little-endian
  integers, wrong binary length, short records, omitted prefix, and reversed
  hash input order. Exact source changes and log hashes are retained in
  `rust-mutations.json`.
- Artifact verification, catalogue consistency and reproduction pass.
- Offline dependency metadata for Linux/amd64 succeeds. Unfiltered metadata
  requires an uncached `addr2line 0.27.1`; this is not an all-platform closure
  claim and does not invalidate the completed scoped builds.
- The full 978-file repository sweep is running against source commit
  `a332eefc719978b387ca00e5b3dc09bc525e3b25`. A first partial attempt failed
  because `readelf` was not on PATH; its logs remain preserved. The corrected
  attempt uses an explicit GNU/LLVM path. No full-suite pass is claimed yet.
- Integration onto main preserves all six implementation/test source hashes.
  The nine native-evidence tests, five focused Rust tests, 12 strict-manifest
  tests, verification, catalogue consistency and reproduction pass. Historical
  snapshot preservation and its blocking check are described in `INTEGRATION.md`.
- Nine native-evidence tests pass: digest/FDE/byte binding, selected-instruction,
  full-body, metadata, relocation, export, source-location and corruption controls.
  The independently reviewed packet preserves 19 FDEs and both native exports.

Only independently authored Rust and offline tools execute. The prefix fixtures
are arbitrary caller inputs, not valid checkpoint captures. Canonical state
serialization, target ABI/allocation identity, quorum/checkpoint acceptance,
network operation and a source-built node/Docker image remain open. No progress
gate or registered comparison window changes.
