# Validation scope

- All-feature Rust tests pass in debug and release: 124 tests each.
- Linux x86-64 all-feature release library build passes. This is a library,
  not a node executable or a Linux runtime acceptance result.
- Clippy with all targets/features and warnings denied, plus rustfmt, pass.
- Five focused Python evidence tests pass, including corruption of all 381
  selected instructions, full-body tails, tables, strings, imports and relocations.
- Six deliberately incorrect Rust implementations compile and fail the intended
  tests. Their changes, commands, source hashes and raw-log hashes are in
  `rust-mutations.json`.
- Full repository sweep: all 976 files passed without restarts;
  15,496 reported tests including 67 skips. See `full-suite.json`.
- Independent review found no actionable issues in byte provenance, routing,
  rejection mapping, decode-before-route ordering or caller-owned I/O disposal.
- Repository verification, catalogue and reproduction results are recorded in
  `build-receipt.json`; an unfinished check is not a pass.
- Hosted CI, state validation, peer authentication, reconnection, a running node
  and a Docker image are not claimed. All progress gates and byte-window counts
  remain unchanged. The required local sweep is complete.

Only independently authored Rust and offline tooling execute. All native target
inspection is static. Current-network compatibility remains unverified.
