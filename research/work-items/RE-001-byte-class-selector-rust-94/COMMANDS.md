# Reproduction and qualification history

Run from the repository root with the materialized pinned target. Environment: Python 3.14.3, installed GNU binutils and Apple LLVM objdump, macOS arm64 and Rust 1.94.1. This packet's Python uses the standard library; the Rust component has no dependencies. No tool installation, global configuration or pin change is required.

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 -O research/work-items/RE-001-byte-class-selector-rust-94/oracle.py
python3 -O research/work-items/RE-001-byte-class-selector-rust-94/audit_indexes.py
python3 -O research/work-items/RE-001-byte-class-selector-rust-94/verify.py --out work/byte-class-selector-review
python3 -O research/work-items/RE-001-byte-class-selector-rust-94/verify.py --check-archive
python3 -O research/work-items/RE-001-byte-class-selector-rust-94/audit_archive.py
cargo check --offline --manifest-path src/node94-byte-class-selector/Cargo.toml --target-dir work/byte-class-selector/cargo-check
rustfmt +1.94.1 --edition 2024 --check src/node94-byte-class-selector/lib.rs src/node94-byte-class-selector/client.rs
python3 -O tools/foundation_byte_range_select.py --check research/work-items/foundation-byte-range-select-94/evidence.json
python3 -m unittest tests.test_foundation_byte_range_select -v
make doctor
make verify
make catalogue-check
make reproduce
```

`--out` must be a fresh directory. The verifier authenticates the full target, reproduces exact complete GNU/LLVM exports and frames, checks all FDE/CIE/caller/relocation bindings and exercises 252 static corruptions. Except for the explicit full-target control, corruptions reach structural checks below the whole-file digest gate. The complete caller bodies are combined into two text exports to preserve all bytes without creating 208 separate files. Raw tool whitespace is retained; only static export whitespace lint is disabled.

The original `static_evidence.py --out <packet>/static` export preceded `oracle.py --freeze`, which required the Rust source directory to be absent. `fixtures/freeze.json` records the 77,412-case oracle/input/expectation identities and timestamp. Rust was written afterwards. No source/oracle/fixture change or post-Rust supplement supplied expectations. The source's complete low-byte relation is checked exhaustively at 65,536 input pairs, with separate high-field witnesses and an all-u32 proof.

Two preliminary attempts were interrupted by the operator while still checking static corruptions. Their logs (`native-1.log`, `native-final.log`) and loaded checker versions (`initial/`) are retained; neither compiled nor executed Rust. On-disk checker updates during the first attempt can make Python's traceback source-line rendering refer to later text; the archived versions identify the actual loaded implementations. Complete FDE/window and relocation/window rescans were replaced inside this packet with prefix-maximum indexes. An exhaustive audit compares every bound FDE query, every actual relocation destination and 735 additional boundaries, and an unselected-FDE overlap control tests completeness. Target records and interpretation did not change. The fresh final qualification is `logs/native-qualified.log`.

Control review also rejected a proposed mask 0x0f→0x1f change in the 0x90 class: OR 0x90 already sets bit 4, so that candidate is equivalent for all 256 low-byte inputs. It was independently checked, never compiled and is not counted. The final control uses mask 0x3f, which exposes bit 5. `initial/status.json` preserves this distinction. No source or oracle fix was required.

Native qualification compiles only new Rust at opt0 and opt3, each twice, with remapped paths, one codegen unit, checked overflow, panic abort and warnings as errors. Exact commands/output/status are in `native/commands.json`; compiler/platform and rlib/client/output hashes are in `native/result.json`. Each actual compiled mutant must exit normally and differ. The stdin client accepts only ID plus two u32 hex inputs; expected outputs never enter it. Outputs are exact full-RAX values without masks. Four comparator controls cover a changed value, missing row, duplicate ID and row ordering.

The deterministic gzip archive (mtime 0) stores a shared line dictionary and per-stream IDs, labels, exact byte counts and hashes. Concatenating referenced lines in order recovers exact stdout. `audit_archive.py` checks every stream and rejects bad byte counts and line indices. Completed reproducible builds and duplicate stdout may be pruned only after direct archive comparison; any such removal is recorded in the ignored task pruning journal. Source, fixtures, commands, results and logs remain intact.

Focused predecessor checker and 10 tests, Cargo offline check, rustfmt, doctor, verify, catalogue-check and reproduce passed. Global exit codes are retained in `logs/global-results.json`. The full test sweep was not rerun on this head. The campaign's separately reported baseline is not claimed as this packet's execution or as completion of skipped Linux qualification. No hosted CI outcome is claimed.

Verify the manifest from the packet directory:

```sh
cd research/work-items/RE-001-byte-class-selector-rust-94
shasum -a256 -c MANIFEST.sha256
```

Read-only scope checks used `gh pr list --repo lalalune/hyperliquid-source --state open --limit 300`, merged PRs with `--state merged --limit 30`, and `gh issue list --state open --limit 200`; metadata is retained in `overlap/`. No push, PR, issue, claim, external message, captured-code execution, chain/key action or instruction emulator was performed by this worker.
