# Validation receipt and replay

Run from the repository root. `validation/checks.json` records terminal exits,
exact argument vectors, output sizes and SHA256 receipts for the local checks;
full unabridged check streams remain in ignored `work/hash-integration-checks/`.
Actual Rust build/test/comparison streams are retained in `observed/`, rather
than only summarized by these receipts.

## Recorded current-component build

```sh
python3 -B research/work-items/RE-007-fixed20-hash-rust-94/verify.py \
  --prepare --snapshot work/hash-fixed-final-v1
python3 -B research/work-items/RE-007-fixed20-hash-rust-94/verify.py \
  --snapshot work/hash-fixed-final-v1 \
  --freeze-sha256 698b62bcd67c59ae1c59dfe52a32f1f4b4202e09f5d08e689c5b30cbbb4dc036 \
  --out work/hash-built-final-v1 \
  --rustc /workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin/rustc
```

Both exited 0. Use fresh snapshot/output names for a new run; a regenerated
snapshot of a later checkout is a new experiment, not this receipt. The frozen
snapshot contains 84 pinned files plus SOURCE-FREEZE.json, including the
current component's source, Cargo manifest/lock, new public hash test, external
margin literal, input-only drivers, oracle/fixtures, operative mutant sources
and the exact guarded runner. Archive replay restores those same bytes.

Observed tool: official rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, host
`x86_64-unknown-linux-gnu`, LLVM 21.1.8. rustc executable SHA256:
`ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`.
The report also pins Cargo/rustdoc binaries and all 66 command argument vectors.
Baseline libraries/drivers used edition2024, `-D warnings`, opt0/opt3,
`-C overflow-checks=yes`; each profile was built twice. Cargo ran offline and
locked in debug/release with explicit matching RUSTC/RUSTDOC, an isolated
Cargo home/target directory, two build jobs and two test threads.

Results: 990 fixed20 supplied-seed cases and 1,980 synthetic compositions per
build, zero mismatches; 13 normal wrong-hash source witnesses, one normal
join-control witness, three driver-framing policy rejections; 41 Cargo tests
per debug/release profile, zero failures and zero doctests. These are authored
Rust executions against frozen mathematical expectations, not captured-node
execution or native instruction evaluation.

The 13 compiled math controls are swapped seeds, big-endian words, big-endian
tail, omitted tail, length21, omitted length byte, zero second word, spurious
length prefix, two compression rounds, saturating addition, markerFE, two
final rounds and u32 truncation. Every witness's exact pre-source wrong value
is required, so a panic, API refusal or arbitrary mismatch cannot pass.

## Offline replay and focused checks

```sh
python3 -B research/work-items/RE-007-fixed20-hash-rust-94/native.py
python3 -B research/work-items/RE-007-fixed20-hash-rust-94/observed.py --current-component
python3 -B research/work-items/RE-007-row-selector-rust-94/observed.py
python3 -B -m unittest discover -s tests -p test_fixed20_hash_rust94.py -v
python3 -B -m unittest discover -s tests -p test_row_selector_rust94.py -v
python3 -B -m unittest discover -s tests -p test_row_lookup_default94.py -v
```

Native authentication checks 796 actual adapter/writer bytes, 224 instruction
extents and six complete body/unwind identities. Twenty individual coordinate
corruptions and one other body corruption reject: these are byte-identity
controls rather than independent semantic execution proofs. New nine tests
also reject four changed source/fixture/input/expected files and an extra
compiler input. Below stream-identity guards, they reject a changed normal H,
a non-distinguishing source mutant, a non-distinguishing join and partial
framing output. Separate old selector controls preserve the 894/7 posthash/API
partition and all original historical receipt pins.

All three focused suites passed: new hash 9/9, old selector 6/6, native row
lookup/default 9/9. Replay and native authentication exited 0. No compiler is
needed by these Python tests. The source/stream archives use strict base64 and
gzip, explicit decoded-payload hashes, exact path sets and per-file hashes.
They contain authored source, synthetic fixtures/output and local diagnostics.

## Repository checks and boundary repair

`make doctor`, `make verify`, `make catalogue-check` and `make reproduce` are
recorded in `validation/checks.json`. `make verify` uses only invocation-local
standard Git LFS clean/smudge/process filters; no persistent configuration or
pinned artifact/import/submodule was changed. Repository-wide `make test` is
coordinated separately and is not included in this packet's result. No hosted
CI, Rustfmt or Clippy result is claimed.

The old selector exact-current-tree check failed on the added hash module
before this build, with exit1 and receipt SHA256
`286dfafb49639fecf5ed1047d9cb81b79fd91471c0eab957af06ef8412cf44dc`.
The minimal correction retains its immutable original 74-file snapshot and
replays the original report; it does not refresh old fixtures or outputs.
See its SNAPSHOT-HISTORY.md. Earlier private hash v1's 40-test receipt remains
unchanged; this 41-test current-tree run is the durable final experiment.

Seed production, native table producer/lifetime and Once/returned-row closure
remain unresolved. No whole-lookup vector or full-scope completion gate is
claimed by any count in this receipt.
