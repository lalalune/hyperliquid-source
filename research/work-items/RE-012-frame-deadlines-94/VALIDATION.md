# Validation scope

- Source base: `a142bea59d2df18f4bbebe4874bdb4c7bc31f514`; exact modified source
  hashes, commands, log hashes and tool versions are in `build-receipt.json`.
- macOS arm64, Rust/Cargo 1.94.1: 53 default codec tests, 69 with `stream`,
  and 81 with all features passed. All 81 also passed in release mode.
- Clippy with all targets/features and warnings denied: passed. Rustfmt: passed.
- Linux x86-64 release library build with all features: passed. This builds
  an rlib, not a node executable; no Linux execution or byte identity is claimed.
- Five focused Python evidence tests: passed. They include 41 individual
  instruction corruptions, source Location/path and timer relocation controls,
  native instruction starts, exact FDE bounds and full input authentication.
- All seven independent source mutations compiled and then failed their Rust
  tests. `rust-mutations.json` retains each diff, source hash and complete output.
- `make doctor verify` baseline: passed. Final `make verify catalogue-check
  reproduce`: passed. No imported evidence or submodule revision changed.
- Full repository sweep: all 973 files passed without retries; 15,480 reported
  tests including 67 skips. Python 3.13.2 with Capstone and GNU/LLVM.
  See `full-suite.json`; raw results and logs are retained under ignored
  `work/frame-deadlines-94/full-suite/`.
- Hosted CI, Docker image and live network acceptance are not claimed.

The new Rust tests use a paused local Tokio clock and scripted I/O. No sockets,
signers or captured executables are launched by these tests. They establish the
bounded API behavior, not the original node's wall-clock scheduling or networking.
All full-component progress gates and byte-comparison counts remain unchanged.
