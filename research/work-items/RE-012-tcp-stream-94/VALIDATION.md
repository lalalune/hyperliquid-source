# Validation scope

- Rust 1.94.1 / Cargo 1.94.1 on macOS arm64: default codec 53 tests passed;
  all-features debug and release each passed 69 tests, including 16 new stream
  tests. Clippy with all targets/features and warnings denied passed; fmt passed.
- Five focused Python evidence tests passed, including native instruction-start
  cross-checks, 21 independent opcode corruptions, EOF data/relocation controls,
  exact FDE bounds and full artifact identity checks.
- All four altered Rust implementations compiled and then failed the stream
  tests. Full test outputs and the single-change recipes are retained in
  `rust-negative-controls.json`. No target execution occurred.
- Linux x86-64 release library build: passed with `stream` enabled. The
  artifact and source hashes are in `build-receipt.json`. This is a library
  build, not a node executable or Linux execution.
- Artifact/signature/import checks and catalogue consistency: passed.
- Repository-wide isolated test sweep: all 972 files passed without retries;
  15,475 reported test cases, including 67 skips. Python 3.13.2, installed
  GNU/LLVM tools and Capstone. See `full-suite.json`; raw logs are retained under
  ignored `work/tcp-stream-94/full-suite/`. Hosted CI is not claimed.
- Docker runtime and real-network acceptance: not performed. The local Docker
  CLI cannot connect to its daemon; this is separate from the missing integrated
  node implementation. No source-built node image is claimed.

The evidence is partial transport reconstruction. No `mapped`, `built`,
`behavior` or `identity` full-component gate is advanced, and no window is added
to `research/byte-windows.json`.
