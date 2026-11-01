# Exact reproduction and chronology

Working directory: repository root. Materialize the pinned node94 LFS object. Environment: macOS arm64, Python 3.14.3, installed GNU binutils and Apple LLVM objdump, Rust 1.94.1. Scripts use Python's standard library; the Rust component has no dependencies. No installation, global configuration or pin change is needed.

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 -O research/work-items/RE-001-checked-subtract-rust-94/oracle.py
python3 -O research/work-items/RE-001-checked-subtract-rust-94/verify.py --out work/checked-subtract-review
python3 -O research/work-items/RE-001-checked-subtract-rust-94/verify.py --check-archive
python3 -O research/work-items/RE-001-checked-subtract-rust-94/audit_archive.py
cargo check --offline --manifest-path src/node94-checked-subtract/Cargo.toml --target-dir work/checked-subtract/cargo-check
rustfmt +1.94.1 --edition 2024 --check src/node94-checked-subtract/lib.rs src/node94-checked-subtract/client.rs
python3 -O tools/foundation_checked_subtract.py --check research/work-items/foundation-checked-subtract-94/evidence.json
python3 -m unittest tests.test_foundation_checked_subtract -v
make doctor
make verify
make catalogue-check
make reproduce
```

A fresh output directory is required. `verify.py` reauthenticates all 91,774,280 target bytes, reproduces static exports via GNU/LLVM, checks complete FDE overlaps/CIE bytes/callers/relocations and performs 39 static corruptions. Except for the explicit full-target corruption, these controls enter structural checks below the whole-file digest gate. The scripts never execute captured bytes or dispatch captured instructions.

Before Rust existed, `python3 static_evidence.py --out <packet>/static` retained complete evidence and `python3 oracle.py --freeze` generated the 9,329 input/expectation rows. The freeze guard required the Rust component directory to be absent. `fixtures/freeze.json` stores timestamp and exact oracle/input/expectation hashes; regeneration must match. No supplementary post-Rust fixture or expectation adjustment was needed.

Only then was independent Rust written. Native compilation and execution use the input-only stdin client and opt0/opt3, each twice with remapped output paths. Exact compiler flags, stdout and status are in `native/commands.json`; compiler/platform identity and matching rlib/client hashes are in `native/result.json`. All warnings are errors, integer overflow checks are enabled, and panic aborts. Repeated correct builds must produce identical artifact and output hashes at each optimization. Every actual compiled mutant must exit normally and differ from the frozen expectations. Four comparator corruptions test values, missing rows, duplicate IDs and row ordering.

The compared format is ID, exact full RAX/error status, and the lossless ordered set of every changed image byte. No normalization masks apply. The client's immutable input copy lets it report unexpected writes even on errors. Expected outputs never enter the client and no expected file is embedded or opened. This compares new macOS Rust against mathematical target-derived expectations, not against execution of the captured Linux binary.

`native/raw-streams.json.gz` is deterministic gzip (mtime 0) with a shared line dictionary and 33 per-stream line-ID sequences, names, exact byte counts and SHA-256 values. Concatenating the referenced lines recovers exact original stdout. The archive audit verifies all streams and rejects corrupted byte counts/indices. Completed duplicate stdout and reproducible ignored native build outputs were pruned only after byte-for-byte archive verification; the ignored journal is `work/checked-subtract/pruning-journal.json`. Source, fixtures, commands, logs and archives remain intact. Raw GNU/LLVM whitespace is retained, with whitespace lint disabled only for static text exports.

All first qualification runs passed. Relevant predecessor checker/11 tests, Cargo offline check, rustfmt, doctor, verify, catalogue check and reproduce passed; global exit codes are recorded in `logs/global-results.json`. The full repository test sweep was deliberately not duplicated and is not claimed.

Manifest verification runs from the packet directory:

```sh
cd research/work-items/RE-001-checked-subtract-rust-94
shasum -a256 -c MANIFEST.sha256
```

Read-only overlap inventories used `gh pr list --repo lalalune/hyperliquid-source --state open --limit 300`, merged PRs with `--state merged --limit 30`, and `gh issue list --state open --limit 200`, retaining metadata in `overlap/`. No push, PR, issue, claim, captured node process, chain/key action or external message was performed by this worker.
