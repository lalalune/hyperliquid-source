# Observed qualification

The base revision is `05bc2de303c05525b71e7e257426e741bc66a390`. Its fee-rate codec exposed only `encode_bits`; its 61 existing encoder vectors passed before this extension. There was no decoder API to run on the base. This work implements the bounded native-backed decoder contract; it does not describe an invented base regression.

## Actual source and static checks

- Rust 1.95.0, aarch64-apple-darwin: both debug and optimized Cargo test invocations exited 0. Each ran two new decoder tests over 925 + 62 frozen cases and the existing encoder test over 61 vectors. The zero-test library/doc harnesses are not additional comparisons.
- Two independent output-directory builds with target `x86_64-unknown-linux-gnu`, locked/offline/release and `CARGO_INCREMENTAL=0` exited 0. Both rlibs have SHA-256 `5ae93488846010124e335d9d00f2eb2751fd2232de69c321c866b11a786c9a6b`. This is byte equality of two reconstructed library builds, not native-binary equality or Linux execution.
- The independently authored exact-rational checker accepted all 62 frozen scalar witnesses. It checks stated expected values; it neither executes native instructions nor substitutes a target oracle.
- The static collector controls exited 0 with 79 completed checks. They exercise malformed byte/metadata/relocation/import/row guards and mocked process/replay failures. These checks do not execute modified native bytes.
- Both GNU collection runs exited 0. The second compared 62 native stdout/stderr files exactly and matched semantic records for 31 complete bodies / 8,850 bytes / 2,192 instruction rows. The only supported replay exceptions are separately retained tool SHA/version and version-stream bytes/hashes; in these observed runs even those tool identities matched.

`validation/` retains actual argv, working directory, timing, exit code and streams. `PATH-PROJECTIONS.json` records the original and published hashes for exact private-path-prefix substitutions. A substituted stream must not be confused with its original raw hash. `observed/` contains unmodified GNU streams using the fixed basename `authenticated-node115`; none of those streams were normalized. `controls.py` is byte-identical to the reviewed and executed private entrypoint named `controls_extended.py`.

## Preserved baseline failures and scope

The first `make doctor` exited 2 because the initial PATH selected Apple's objdump and lacked GNU readelf. With the installed GNU tools first in PATH, doctor, verify and reproduce exited 0. Base `make catalogue-check` exited 2 for stale generated README content; its output is retained. Generated catalogue output is refreshed in this change and checked separately at final integration.

Full `make test` was not run: the repository's broad suite includes captured-instruction evaluators outside this static-only run. Focused Rust host tests and static-data collector controls are the tests actually observed. The PR uses `[skip ci]`; no hosted CI or container result is claimed. No captured node or visor, emulation, live chain, signing, allocator/formatter/unwind callbacks or instruction evaluator was executed. No progress gate is requested.

The Rust test receipt predates the crate README update; production source, Cargo manifest, lockfile and test vectors retain their qualified hashes. All original pre-source JSON expectations remain byte-identical; their TSV representations were produced after source authoring without recomputing scalar expected values.
