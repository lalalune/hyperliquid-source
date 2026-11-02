# Actual validation

The captured node was only read/disassembled. These results do not claim full
repository tests, hosted CI, target execution or whole-consensus equivalence.

- Before source changes: Rust1.94.1 component tests passed36 unit+9 existing
  integration tests. The first attempt passed all45 but failed to launch
  rustdoc because only RUSTC was pinned. With the same pinned toolchain's
  RUSTDOC explicitly supplied, the complete command passed (zero doctests).
- After changes: `build.py` ran offline/locked component tests in debug and
  release, each36 unit+9 existing+2 new integration tests, zero failures.
  It compiled the standalone `driver.rs` against the real component library,
  never a replacement/fake workspace.
- All783 frozen preimage/digest cases matched in each profile. Debug/release
  raw output SHA256:
  `f0f2921b469eb9fd7d1147facbe684e84c8307c3f3c7d65e7e5fcce106372f35`.
- Six temporary compiled behavioral mutants mismatched269 (250 marker),
  565 (big endian),783 (extra label),782 (hash moved),783 (omitted signer),
  783 (tag zero) cases. Raw outputs and source hashes are retained.
- `verify.py` and `python3 -O verify.py` each passed97 negative controls and
  two fresh GNU/LLVM regenerations equal to retained exports; result JSON is
  byte-identical. The verifier also checks tag1 literal209f84 and the credited
 24-round table without altering the frozen derivation.
- Pinned Cargo fmt check passed with the toolchain bin directory on PATH.
  An earlier Cargo invocation without that PATH could not locate cargo-fmt;
  no source was changed by that failed launch. Pinned Clippy all targets
  with `--offline --locked -- -D warnings` passed.
- Tracked changed-file diff checks and no-index checks for new text files passed.
  The old vote-path manifest validates after its README-only annotation;
  fixtures, generator and all other old packet files remain unchanged.
- All28 real-component source/manifest/lock hashes still equal the successful
  build receipt. New proof/derivation files had one extra EOF blank line,
  removed with a reversible, explicit POST-FREEZE-NORMALIZATION receipt.
  PRE-RUST-FREEZE and all expected vectors/native exports remain unchanged.

Reproduction commands and tool requirements are in README. Actual Cargo/rustc
commands and compiler/test stdout/stderr are retained in
`rust-validation/commands.json.gz`; driver stdout is referenced by its existing
raw TSV filename and hash to avoid duplication. Only repository, scratch and
toolchain paths are replaced with placeholders. Successful source scope and hashes are in
`rust-validation/results.json`; all baseline/mutant raw comparisons are gzip
TSV files. Build timing and test output ordering need not be deterministic;
fixture bytes, source output bytes, and native exports are checked separately.

The reviewer should read the short source API and PROOF before the full native
exports. A test of the independent Rust implementation is not a target run.
