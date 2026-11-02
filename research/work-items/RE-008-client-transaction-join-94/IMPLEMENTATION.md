# Qualified client transaction join

The actual dependency-free `node94-consensus-admission` crate now implements the
conditional join in `client_transaction_join`. It transfers an opaque `Arc<B>`
block/proof and all 12 raw time bytes, preserves supplied row identity without
calling either view, and otherwise looks up requests in their given order.
Duplicates retain actual shared value Arcs. The first missing hash returns that
exact hash, releases the temporary prefix and consumes the block. Empty absent
hashes create new empty rows and skip map access. This is one complete value
operation, with explicit safe view/span/reservation refusals.

Read [PROOF.md](PROOF.md) for the native premises and
[rust-validation/SOURCE-PROOF.md](rust-validation/SOURCE-PROOF.md) for the source
bridge. The original 49 pre-code inputs, independent 361-case corpus and prior
PR999 credit remain unchanged. The source uses only the real baseline package
at `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; its manifest/lock and existing
APIs are unchanged. There is no pending QC/block/batch/bincode dependency.

## Actual qualification

Author and coordinator each completed the exact amended frozen harness in
separate fresh output roots. Per run:

- 141 commands: 132 exited 0; nine deliberately invalid-input checks exited 2.
- Debug and release each passed 36 existing library tests and 11 new integration
  tests. Formatting, real Cargo metadata admission and clippy passed.
- Baseline and clean same-path repeat each matched all 361 expected outputs in
  both profiles, with zero mismatches.
- All 17 behavioral mutants compiled and produced complete 361-row streams in
  both profiles; all were distinguished. Together with the four baseline/repeat
  streams, that is 38 value streams per run.
- Eight comparator corruptions were rejected. Eight malformed-input cases and
  an extra argument produced exit 2 with no stdout; empty input succeeded empty.
- All 97 toolchain bin/lib files, source and harness remained unchanged.

The mismatch count is identical in debug and release:

| Compiled mutant | Differing cases |
| --- | ---: |
| eager hash view | 26 |
| eager map view | 45 |
| empty hashes invoke map | 8 |
| sorted requests | 129 |
| deduplicated request runs | 9 |
| reversed requests | 98 |
| last missing selected first | 59 |
| copied value object | 152 |
| copied supplied rows | 26 |
| retained failed block | 155 |
| retained failed prefix | 145 |
| changed missing hash | 155 |
| changed raw time | 186 |
| native row width 39 | 6 |
| rejected final valid count | 1 |
| wrapped row-size multiplication | 1 |
| supplied empty treated as absent | 4 |

The coordinator compared every full value stream byte-for-byte with the author
run and rehashed 76 compiled-artifact references per run, including private
first-build archives. Within each run, same-path repeated rlib/client bytes
matched in both profiles. Across author/coordinator roots, both rlibs and the
release client matched; debug clients differed. Bytes were not normalized and
no cause for that difference is asserted. The coordinator initially expected
37 library tests in its comparison script; actual logs showed 36. It retained
that first comparison rejection and corrected only its census, without changing
source, build results or expected values.

## Review correction and retained evidence

The first source freeze preceded compilation. Independent review then identified
missing direct block-pointer observation and loss of first-build binary bytes
before same-path replacement. [SOURCE-AMENDMENT.json](SOURCE-AMENDMENT.json) and
[the exact diffs](rust-validation/amendment-1/README.md) preserve that chronology.
The amended client compares the returned block pointer with the original Weak
pointer on every success; an added test covers the newly constructed-rows path.
The amended runner archives first and repeat compiled bytes before replacement.
The production module, native proof, corpus and 17 mutants did not change.
No Rust compilation was attempted under the first freeze, and both actual
amended build runs passed. Original driver/harness/freeze and old test bytes
remain available; the active entrypoint is `build_amended.py`.

The public [author receipts](rust-validation/receipts/results.json) retain exact
metadata and all 282 command stdout/stderr references as 79 unique gzip streams.
The [root comparison](rust-validation/root-comparison.json) records the separate
run. [PUBLIC-ARCHIVE.json](rust-validation/PUBLIC-ARCHIVE.json) defines availability:
compiled rlib/client archives are retained **privately** and their metadata hashes
remain public. Client binaries contain private home paths; no compiled binary is
masked or published. `compiled-artifacts/...` references in raw result metadata
refer to the private qualifying receipts root, not a missing public command
stream. A fresh reproduction creates its own compiled archives.

## Reproduce the recorded host qualification

From the repository root, use a fresh direct `/tmp` child and a fresh private map
path. `TOOLCHAIN` must name the exact pinned Rust 1.94.1 installation; the recorded
runner also uses the admitted macOS linker/SDK. Source APIs remain ordinary safe
Rust; this pinned-host reproduction is deliberately stricter than a portable
Cargo build.

```sh
python3 -B research/work-items/RE-008-client-transaction-join-94/rust-validation/build_amended.py \
  --toolchain /path/to/pinned/rust-1.94.1 \
  --out /tmp/hl-transaction-join-replay \
  --private-map /tmp/hl-transaction-join-replay-private-map.json \
  --source-freeze-sha 2de24db3687bb778404bee347fa8c26eb70b6cc319a094fab77d7c07fd9ee427
```

The harness admits the exact actual crate, original and amended freezes, original
source reconstruction, fresh Cargo home, ancestor configurations and full
payload pins before compiling. It executes only authored Rust. It does not run
the captured binary, emulate instructions, run the old evidence integration
case or run the full repository suite. A failure stops qualification and retains
completed command streams; compiled artifacts must stay private unless separately
inspected for publication.

Finite host tests do not discharge native memory/tree/refcount/callee-frame
premises. Native allocator/layout/atomic thresholds, arbitrary Drop effects,
exception paths, whole-client behavior and fully hermetic host builds remain
outside the claim. The independent reviews share one captured project lineage.
