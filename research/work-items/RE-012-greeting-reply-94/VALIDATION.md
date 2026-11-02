# Validation scope

- Rust/Cargo 1.94.1 on macOS arm64: 53 default codec tests, 69 with stream,
  114 with all features. All 114 also pass in release. Clippy with all targets,
  features and warnings denied, plus rustfmt, pass.
- Linux x86-64 all-feature release library build passes. This is an rlib,
  not a node executable or a Linux runtime result.
- Seven Python evidence tests pass: 428 selected instruction corruptions,
  body/table/relocation/source-path controls, GNU/LLVM instruction starts,
  corpus identity controls, full artifact authentication and record reproduction.
  The added import-name controls also pass their final focused rerun.
- Nine wrong Rust decoder implementations compile and then fail the intended
  tests. Diffs, commands, source hashes and full output are retained in
  `rust-mutations.json`.
- 35,023 comparisons to pre-existing frozen mathematical fixtures pass. Two
  nonrepresentable counter rebases are explicitly excluded; the initial two
  mismatches are retained. Source corpora are unchanged. See `replay-result.json`,
  `replay-initial-result.json`, and `fixtures/sources.json`.
- Baseline make doctor/verify and final make verify/catalogue-check/reproduce
  pass. No imported evidence or submodule revision changed.
- Full repository sweep: all 975 files passed without restarts; 15,491 reported
  tests including 67 skips. See `full-suite.json`; raw logs remain under ignored
  `work/greeting-reply-94/full-suite/`.
- Hosted CI, peer acceptance, real-network operation, a source-built node and
  Docker acceptance are not claimed. All milestone gates and byte counts are
  unchanged. The required local sweep is complete; hosted CI remains separate.

Build/source/artifact hashes are in `build-receipt.json`. New Rust validation
executes only the independent code with synthetic input and scripted I/O.
