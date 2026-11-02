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
- The complete repository sweep for this change has not started. The
  greeting-policy sweep has passed; the EVM-decoder sweep is still active.
- Nine native-evidence tests pass: digest/FDE/byte binding, selected-instruction,
  full-body, metadata, relocation, export, source-location and corruption controls.
  The independently reviewed packet preserves 19 FDEs and both native exports.

Only independently authored Rust and offline tools execute. The prefix fixtures
are arbitrary caller inputs, not valid checkpoint captures. Canonical state
serialization, target ABI/allocation identity, quorum/checkpoint acceptance,
network operation and a source-built node/Docker image remain open. No progress
gate or registered comparison window changes.
