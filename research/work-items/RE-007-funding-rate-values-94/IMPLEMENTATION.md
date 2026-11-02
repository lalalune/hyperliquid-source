# Qualified supplied-sample rate values — active review entry

The real dependency-free `no_std` crate is
[`src/node94-funding-rate-values`](../../../src/node94-funding-rate-values).
It implements one supplied-sample raw-rate operation plus the selected caller's
absence-to-positive-zero projection. Ordered rounding, signed zeros and NaN
payloads are preserved with integer arithmetic. The native scope remains the
conditional node94 relation in [CONTRACT.md](CONTRACT.md) and
[PROOF.md](PROOF.md), not live funding policy or a whole-node gate.

**Read [SOURCE-PROOF-ADDENDUM.md](SOURCE-PROOF-ADDENDUM.md) with the original
[SOURCE-PROOF.md](SOURCE-PROOF.md).** Independent source review corrected the
written specialized ratio exponent range to `-53..0`. Production already
computed that range correctly. The documentation-only
[amendment receipt](SOURCE-PROOF-AMENDMENT.json) preserves the original proof
and source freeze. No code, oracle or expectation changed for this correction.

## Chronology and independent checks

The immutable pre-source phase contains three complete native FDEs (2,038
bytes/484 rows), explicit memory/helper/Intel SSE premises, and3,153 raw-bit
expectations authored with exact Fractions and adjacent-representable distance.
Its actual author qualification passed561 static controls, two native
regenerations and two exact corpus regenerations. The coordinator independently
read/replayed this phase and recomputed every expected output before authoring
production was authorized. Its freeze is
`9549a435f609bcaed7293a0eedf7fd3961573bb0d9e07ab3b05a8effd720444b`.

The new source, input-only client and build harness then received a separate
freeze, `e4ea0b5dfd219feda46b64cb1ffc87dcfab275c9b5613905d9f33ad453f88ef9`.
Source preparation ran exactly three commands: text formatting, real offline
Cargo lock generation, and actual isolated Cargo metadata. These did not
compile or execute production. The proof addendum and independent source peer
preceded the coordinator's exact source/build gate. Production qualification
started only after that gate. All original35 pre-source files and all5 source
plus9 harness/graph files remain unchanged.

`build.py` authenticates those frozen files. **It does not rerun the static
native verifier.** That replay occurred in the earlier pre-source phase; this
later result is the qualification of host-compiled value reconstruction.

## Actual qualification result

The author run completed150 commands:138 exited0 and12 deliberately malformed
input/argument checks exited2. No required check failed. The complete command
ledger and content-addressed raw stdout/stderr are retained under
[`rust-validation/author`](rust-validation/author), with
[results.json](rust-validation/author/results.json),
[commands.json](rust-validation/author/commands.json) and the
[receipt audit](AUTHOR-RECEIPT-AUDIT.json). There are300 raw stream references,
87 distinct raw streams (3,061,879 uncompressed bytes), stored in214,381 gzip
bytes. The receipt copy preserves every original byte; no output was normalized.

Both debug/release profiles passed3 private arithmetic and8 public value tests.
The actual-crate format and Clippy checks passed. All3,153 frozen inputs matched exactly in both
profiles of each of two physically distinct clean build roots. Ten comparator
corruption controls rejected changed/omitted/reordered outputs. Eleven malformed
stdin cases and an extra argument produced no successful output; empty input
produced empty output.

All18 source mutants actually compiled and emitted complete streams in both
profiles; every one differed from the frozen expectations in both. Difference
counts per profile, in harness order, were17,86,1348,15,58,16,452,6,45,60,791,2,
321,634,599,1438,32 and223. These exercise reduction order/seed/completeness,
defaults/absence, mean and tie rounding, NaN priority/payload, signed-zero clamp,
finite guards/bounds, multiplier/final factor, projection and gradual underflow.
They are observed controls, not an exhaustive generic floating-point validation.

The coordinator independently ran the same exact harness. Its final comparison
receipt is identified by SHA-256
`beeab972e35d3c98f3a0fa3774a2d37edceefff7f01da3e3d63a77fb0c345e9e`.
It rehashed600 command-stream references and160 built artifacts across the two
runs, and matched all40 complete value streams per run, including mutant
streams. Coordinator receipts/review are a separately appended review phase;
the author archive does not modify their originals.

Raw library artifacts match across the two clean roots in both profiles, and
release clients match. Debug clients differ. The same result holds across
author/coordinator runs. No masks or normalization were applied, and no debug
client reproducibility claim is made.

## Reproduce the source phase

Use the already installed toolchain whose97 `bin`/`lib` payload files match
[TOOLCHAIN-PINS.json](TOOLCHAIN-PINS.json). No installation or network step is
part of this qualification. Choose a fresh direct child of canonical `/tmp`
and a fresh private-map path outside the packet:

```sh
python3 -O -B research/work-items/RE-007-funding-rate-values-94/build.py \
  --toolchain /absolute/path/to/matching/installed/toolchain \
  --out /tmp/fresh-funding-rate-replay \
  --private-map /absolute/private/funding-rate-path-map.json \
  --source-freeze-sha e4ea0b5dfd219feda46b64cb1ffc87dcfab275c9b5613905d9f33ad453f88ef9
```

The harness rejects symlinked inputs and ancestor Cargo configuration/manifests,
checks the actual isolated workspace/target paths, uses an empty Cargo home
offline/locked, and directly links the real library into the input-only client.
It authenticates source and toolchain again after qualification and retains
failures before stopping. Runtime caches are excluded from distribution; the
author manifest contains none. Private home paths and credentials are absent.

Native correspondence still requires valid selected containers/helper frames
and the explicit Intel round-to-nearest-even, DAZ/FTZ-off, masked-exception
relation. Integer production does not measure a target CPU/MXCSR. Allocation,
generic map/hash recovery, exception flags/traps, native ABI or compiler-byte
equivalence, scheduler completeness and economic interpretation remain outside
scope. No captured node/Visor executable or instruction evaluator ran.
