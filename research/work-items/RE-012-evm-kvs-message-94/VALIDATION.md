# Validation scope

- All-feature Rust tests pass in debug and release: 147 tests each.
- Linux x86-64 all-feature release library build passes; this is an rlib,
  not a node executable or Linux runtime acceptance.
- Clippy with all targets/features and warnings denied, plus rustfmt, pass.
- Five focused native-evidence tests pass, including selected-instruction,
  full-body, table/string/relocation and vtable corruption controls.
- Ten incorrect Rust implementations compile and fail intended tests. Exact
  changes, commands, source hashes and log hashes are in `rust-mutations.json`.
- Artifact verification, catalogue consistency and reproduction checks pass.
- Full repository sweep: all 977 files passed without restarts;
  15,501 reported tests including 67 skips. See `full-suite.json`.
- An independent read-only review found no actionable decoder issues. The
  transfer guard was separately checked against its native counter/store path.
- Hosted CI, database apply/compaction, full state validation, network operation
  and node/Docker acceptance are not claimed. All milestone gates and compared
  byte-window counts remain unchanged. The required local sweep is complete.

The tests execute only independent Rust and offline tools. Counter tests near
100 GB/u64 boundaries use private synthetic counter seeds, not huge buffers or
captured target execution. Native allocation/ABI identity remains unmeasured.
