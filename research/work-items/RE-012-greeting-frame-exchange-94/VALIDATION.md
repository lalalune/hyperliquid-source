# Validation scope

- macOS arm64, Rust/Cargo 1.94.1: 53 default tests, 69 with `stream`, and
  93 with all features passed. All 93 also passed in release mode.
- Clippy with all targets/features and warnings denied: passed. Rustfmt: passed.
- Linux x86-64 release library with all features: built, not executed. No
  source-built node, Linux behavior or target machine-code equivalence is claimed.
- Four focused Python evidence tests: passed. They check all 63 selected
  instruction mutations below the digest check, GNU/LLVM instruction starts,
  fresh record reproduction and full target identity.
- Seven changed Rust implementations compiled and then failed the greeting
  tests. Each diff, source hash, command and output is in `rust-mutations.json`.
- Baseline `make doctor verify`: passed. Final `make verify catalogue-check
  reproduce`: passed. No imported evidence or submodule revision changed.
- Full repository sweep: all 974 files passed without retries; 15,484 reported
  tests including 67 skips. Python 3.13.2 with Capstone and GNU/LLVM.
  See `full-suite.json`; raw results and logs are retained under ignored
  `work/greeting-exchange-94/full-suite/`.
- Hosted CI, Docker image, actual connection, semantic reply validation and
  synchronization acceptance are not claimed.

Exact source hashes, build artifact hash, commands and log hashes are in
`build-receipt.json`. The new tests use deterministic scripted I/O and a paused
Tokio clock. They launch no captured executable, socket or signer. The new
source stops at the reply-frame boundary; all component gates and compared-byte
counts remain unchanged.
