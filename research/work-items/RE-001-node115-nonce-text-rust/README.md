# RE-001: node #115 nonce text values

This packet accompanies the independently authored
[`node115-nonce-text`](../../../src/node115-nonce-text/README.md) component.
The selected operation admits a canonical-u64 list prefix, preserves its
values and successful consumption, and checks the credited strict ordering
relation. It is a bounded value projection, not the native parser/error ABI,
outer two-field decoder, public nonce policy or whole-node reconstruction.

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The existing [provider proof](../RE-001-node115-nonce-text-provider/PROOF.md)
binds provider `0x1e29f50..0x1e2a28d` and ordering wrapper
`0x2923da0..0x2923ee1`; the wrapper calls the provider. Credit remains with
PR #1396 for that proof, #1003 for native ordering and #1694 for the existing
Rust ring implementation. No new native mapping credit or completion gate
is requested.

[CONTRACT.md](CONTRACT.md) retains every reviewed v3 semantic premise and
limitation. In particular, NotAdmitted is logical non-admission, without a
universal native ordinary-error termination claim. Successful correspondence
requires native premises and successful own host capacity/reservations.

The 71,175 pre-source input/expected frames and 55 resource arithmetic rows
are copied without regeneration. [PRE-SOURCE-IDENTITIES.json](PRE-SOURCE-IDENTITIES.json)
records their identities and the independent pre-source review. The model,
generator and expectations are external to the Rust client. Resource rows
describe chosen host arithmetic; they are not native OOM observations.

The input-only client reads terminated ASCII transport lines:

```text
case_id<TAB>mode_decimal<TAB>depth_decimal<TAB>input_hex_or_dash_for_empty
```

It emits either `case_id<TAB>parsed<TAB>consumed<TAB>values_or_dash` or
`case_id<TAB>classification`. Only Parsed exposes consumption and values.
`validate.py` compares complete raw output against the frozen expectations;
`check_comparator.py` separately challenges the comparator with corrupted
output bytes. The 27 transport controls are CLI checks, not extra native
semantic coverage. Actual compiled source controls need separate source,
patch, build and execution evidence.

## Actual qualification

Before this change the repository had the ordering library and native provider
proof, but no `src/node115-nonce-text` decoder. The new source uses that real
library through a safe initialized-slice adapter. Its only dependency is the
existing local ring crate; the actual Cargo lock contains those two packages.

With Rust 1.95.0 on `aarch64-apple-darwin`, debug and release clients each
matched all 71,175 frozen output frames byte for byte. Each profile also
passed 27 separate CLI transport controls. One Rust unit test per profile
checked all 55 pre-source resource arithmetic rows without allocating their
represented sizes. Linux `x86_64-unknown-linux-gnu` debug and release rlibs
compiled successfully; no Linux executable was linked or run.

Twelve actual library mutations were independently compiled in both profiles.
All 24 executions completed with well-formed output and a mismatch at a named
frozen witness. Controls cover leading zeros, overflow, whitespace, early
ordering, equality, depth/mode precedence, prefix exhaustion/consumption,
signed narrowing and negative zero. Build errors and crashes were not counted
as successful controls; none occurred. The separate output comparator passed
17 pure-data controls both normally and under Python `-O`.

`make verify`, `make catalogue-check` and `make reproduce` passed after the
change. The preceding scoped baseline ran 73 test files with zero file
failures and documented environment-dependent skips; the five relevant
catalogue tests passed again after registering the component path. Full
`make test` was not run: three captured-instruction evaluator files were
excluded from this static-only task. [Repository checks](validation/repository.json)
retain the exact scope, commands, outcomes and exclusions.

See [VALIDATION.json](VALIDATION.json), [build commands and logs](validation/builds.json),
[baseline outputs and transport bytes](validation/baselines.json), and each
mutation result under `validation/mutants/`. Complete raw parser output streams
are retained as gzip files. Debug/release streams were stored once only after
byte equality was verified; the two compiled binaries and run receipts remain
distinct. Commands and build-log views replace machine path prefixes with named
roots. Parser output and transport bytes have no normalization. Original raw
build-log hashes are retained alongside the disclosed portable views.

The earlier provider verifier first rejected current parser dependency hashes.
Its accompanying [migration record](../RE-001-node115-nonce-text-provider/migration-validation.json)
updates only the necessary metadata and preserves the proof, collector,
checker, historical results and native exports. Fresh static exports matched
all 27 original output files; only two parser-hash fields in the records
changed. Both normal and `-O` verification retained 168 rejection controls.
Those are prior proof validation, not new native-byte recovery credit.

## Reproduce the own-source comparison

From the repository root on the recorded macOS host, with Rust 1.95.0 already
installed, build each profile using the exact commands in `validation/builds.json`.
For example:

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-nonce-text/Cargo.toml --target aarch64-apple-darwin --lib
cargo +1.95.0 build --offline --locked --manifest-path src/node115-nonce-text/Cargo.toml --target aarch64-apple-darwin --lib --bin nonce-text-client --release
```

Pass the actual newly built client's path and SHA-256 to the comparator. Its
output directory must be new; it preserves raw input/output and command records.
The client receives input bytes through stdin only. Repeat with the debug
binary and `--profile debug` to reproduce both comparisons.

```sh
python3 -B research/work-items/RE-001-node115-nonce-text-rust/validate.py \
  --corpus research/work-items/RE-001-node115-nonce-text-rust \
  --client /absolute/path/to/own/release/nonce-text-client \
  --client-sha256 ACTUAL_SHA256 --profile release --out work/nonce-text-release
python3 -B research/work-items/RE-001-node115-nonce-text-rust/check_comparator.py \
  --corpus research/work-items/RE-001-node115-nonce-text-rust \
  --out work/nonce-text-comparator.json
```

For each compiled control, copy the two real crate directories into a fresh
isolated tree, apply its `controls/*.patch` to the copied library only, and
build the unchanged client against that tree in both profiles. Preserve the
original lock and local path dependency. Each `validation/mutants/*.json`
records the exact source hashes, build argv, binary identity and named witness.
The comparator's `--mutation-receipt` accepts a JSON record containing `name`,
`witness_ids`, `baseline_binary_sha256`, `mutant_binary_sha256`, `build_exit_code`, and
`baseline_source`, `mutant_source`, `patch`, `build_receipt` objects with `path`
and `sha256`. Supply the actual new build's identities, not retained binary
hashes. A control passes only for complete valid output with a named mismatch.

The corpus can be independently regenerated from the packet directory into a
new directory with `python3 -B generate.py --out NEW_DIRECTORY`; compare its four file hashes with
`PRE-SOURCE-IDENTITIES.json`. It must never be regenerated from Rust output.

No Linux execution, allocator-failure test, captured execution, original
error-state equivalence, byte equality, hosted CI or whole-node completion is
claimed. All full-component gates remain false. Exact native error cursors,
opaque-helper termination and the outer two-field decoder remain future work.
