# Reproduction commands and chronology

All commands run from the repository root unless noted. Requires the clean materialized pinned node94 artifact, Python 3.14.3, GNU binutils and Apple LLVM objdump, and Rust 1.94.1. No third-party Rust/Python package is needed by this packet. On this macOS arm64 host:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 -O research/work-items/RE-001-bounded-byte-selector-rust-94/oracle.py
python3 -O research/work-items/RE-001-bounded-byte-selector-rust-94/supplement.py
python3 -O research/work-items/RE-001-bounded-byte-selector-rust-94/verify.py --out work/bounded-byte-selector-review
python3 -O research/work-items/RE-001-bounded-byte-selector-rust-94/verify.py --check-archive
python3 -O research/work-items/RE-001-bounded-byte-selector-rust-94/audit_archives.py
cargo check --offline --manifest-path src/node94-bounded-byte-selector/Cargo.toml --target-dir work/bounded-byte-selector/cargo-check
rustfmt +1.94.1 --edition 2024 --check src/node94-bounded-byte-selector/lib.rs src/node94-bounded-byte-selector/client.rs
python3 -O tools/foundation_helper_low_byte_equality.py --check research/work-items/foundation-helper-low-byte-equality-94/evidence.json
python3 -m unittest tests.test_foundation_helper_low_byte_equality -v
make doctor
make verify
make catalogue-check
make reproduce
```

Use a fresh `--out` directory. The verifier authenticates the full target, regenerates both decoder exports and retained FDE records, compares them byte-for-byte, runs static corruption controls below the full-target digest gate, regenerates frozen fixtures, and builds/runs only newly authored Rust. Exact compiler arguments, outputs and platform versions are in `native/commands.json` and `native/result.json`. Compiler warnings are errors. Optimizations 0 and 3 each use two separate output paths, remapped to `/component`; rlib/client hashes must repeat at each optimization. The input-only client receives TSV on stdin, emits ID and exact complete RAX/error status, and has no expected-output input. It does not execute captured bytes.

Initial preparation generated GNU/LLVM exports with `python3 static_evidence.py --out <packet>/static` and froze the oracle with `python3 oracle.py --freeze` before the Rust component directory existed. `logs/pre-rust-fixture-review.log` records a pre-Rust boundary expansion and the superseded first freeze identity; `fixtures/freeze.json` is the final 4,716-case pre-Rust freeze. Neither that oracle/corpus nor Rust changed after final freeze/source creation, respectively.

The first native run used only those 4,716 cases and stopped when `checked-selected-add` survived. It had passed four correct runs and 25 earlier compiled controls. Its 30 exact streams, compiler commands, control source, failure log and mismatch counts are retained under `initial/` and `logs/native-1.log`. A surviving control is a coverage finding, not a passing negative control. The address-wrap case was absent from the original corpus.

`supplement.py --freeze` then created 24 explicitly post-Rust inputs. They use the already frozen oracle and an independent direct witness: low=2^64-missing, positive step<=256<511, so the selected wrapped address is step-missing. Direct image interval membership/byte indexing must agree with the original oracle before any supplemental expectations are written. `fixtures/supplement.json` records timestamp, source identities and every fixture/generator hash. The full native run was repeated from scratch with 4,716 original + 24 supplemental cases. `logs/supplement-freeze.log` and `logs/native-final.log` preserve that distinction.

`make doctor` initially failed because `/usr/bin/objdump` was Apple LLVM and `readelf` was absent from PATH. `logs/doctor-initial-path-failure.log` is retained. It passed with installed GNU binutils prepended; no installation or global configuration changed. `make verify`, catalogue check and reproduce passed. The full repository test sweep was intentionally not duplicated: this packet claims only the 15 focused predecessor tests and new validation.

Both `raw-streams.json.gz` files use deterministic gzip (mtime 0) containing a shared line dictionary plus per-stream line IDs, labels, exact byte counts and SHA-256. This is lossless: concatenate referenced lines in order to recover original stdout. The audit checks every retained stream and rejects corrupted byte counts and line indices. No masks or result normalization are applied. Raw GNU/LLVM text retains tool whitespace; `.gitattributes` disables whitespace lint only for those unmodified static exports.

Verify the manifest from the packet directory:

```sh
cd research/work-items/RE-001-bounded-byte-selector-rust-94
shasum -a256 -c MANIFEST.sha256
```

Live scope inventories used read-only `gh pr list --repo lalalune/hyperliquid-source --state open --limit 300`, recent merged PRs (`--state merged --limit 30`), and open issues (`gh issue list --state open --limit 200`), with metadata fields retained in `overlap/`. Address and semantic review is recorded in `overlap/summary.json`. No issue, claim, PR, push, node process, network/chain action or key operation was performed by this packet's authoring worker.
