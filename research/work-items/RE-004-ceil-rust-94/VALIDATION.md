# Validation record

Run date: 2026-11-02 Asia/Seoul. Source base:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Host: macOS arm64,
Python 3.14.3, rustc 1.94.1 (`e408947bfd200af42db322daf0fadfe7e26d3bd1`),
GNU binutils 2.47 and Apple LLVM 17.0.0. The compiler's own LLVM is 21.1.8;
it is distinct from the Apple disassembler. Full compiler output is retained.

All commands run from the repository root. For repository checks, PATH starts
with `/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin` and
`LLVM_OBJDUMP=/usr/bin/objdump` selects the available Apple LLVM provider.
No shell profile or global provider registration was changed. The existing
Capstone 5.0.7 install supports the baseline suite; the new verifier has only
Python standard-library dependencies plus the pinned Rust compiler.

| Check | Observed result |
| --- | --- |
| `make doctor verify catalogue-check reproduce` | Exit 0; artifacts/signatures, imports, pins and generated catalogues pass; imported inventories and classifications reproduce |
| New Rust `--test` at optimization 0 and 3 | Two tests pass at each level; retained logs include all test names |
| Input-only native clients at optimization 0 and 3 | Both APIs agree with every expected bit pattern on all 33,066 inputs; zero mismatches |
| Four compiled semantic mutants | 405 / 8,226 / 9 / 10 mismatching inputs, matching the predecessor controls; first actual counterexamples retained |
| Repeated optimized rlib build | Raw SHA-256 identical, no normalization |
| Client framing rejection | A three-byte input exits nonzero with the expected partial-word error and no result bytes |
| Ordinary vs optimized Python verifier | Both complete successfully; the initial two records were byte-identical. The final record adds actual first-mismatch result words |
| `make test` | Full 971-file isolated suite started; still running when this preparation-time record was written. No full-suite pass is claimed |

`commands.json` contains the final native build, run and static-binding commands
and return codes. `<repo>` substitutes only the checkout's absolute root;
commands execute with that repository as cwd. The original per-command stdout,
stderr, input/expected words, native output words, compiled clients/rlibs and
mutant sources remain in the ignored output directory selected by `--out`.
`result.json` retains source, input, expected-output and native-output hashes.
Unit-test stdout is retained byte-for-byte as JSON strings in `unit-logs.json`;
compiler text output is retained separately.

The native runs execute newly authored Rust only. The captured ELF is parsed
and authenticated by the predecessor verifier. No captured-code execution,
target instruction emulator, host floating-point `ceil` oracle, Linux binary
comparison, hosted CI or container success is claimed. No acceptance gate or
byte-comparison registry is changed.
