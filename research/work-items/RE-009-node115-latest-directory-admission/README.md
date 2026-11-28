# Admit only directories to latest checkpoint selection

A numeric regular file inside the checkpoint container used to be counted as a candidate height by the reconstructed latest loader. This changed the result from “no checkpoints to load” to “unable to load any current checkpoint”, even though the directory contains no checkpoint entries. Both #115 latest loaders first pass the container through directory-only enumeration. The Rust entry point now checks directory metadata before extracting a candidate name. A directory-open error remains observable and a failed individual entry is skipped.

The calls at `0x4468eae` and `0x59ffac1` both use relocation `0x64e0968 → 0x1501290`. That wrapper calls the common collector and then `0x15b58c0`, whose `0x15b5902` call reaches the directory filter at `0x153f470`. The selected test at `0x153f4d8` admits a row with its directory flag set. The [startup admission study](../RE-012-node115-startup-directory-admission/README.md) binds the producer of that flag to directory-mode metadata and establishes per-entry rejection. The [canonical-height work](https://github.com/lalalune/hyperliquid-source/pull/7265) addresses formatting and numeric parsing after admission. This patch applies only at the preceding enumeration boundary.

The filesystem regression distinguishes a container with only numeric regular files, one with an incomplete numeric directory, and one with a completed directory.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-latest-directory-admission/verify.py
cargo test --offline --locked --manifest-path src/node115-db/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-db/Cargo.toml --test integration latest_checkpoint_parses_only_directories
```

The [offline log](offline-log.txt) preserves the failing baseline, static check and both passing Rust runs. The captured node is read as ELF data.
