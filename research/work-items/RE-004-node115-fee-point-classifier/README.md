# RE-004: node #115 fee point classifier

This packet supports the new, independently authored
[Rust point classifier](../../../src/node115-fee-point-classifier/README.md).
It reconstructs the first numerical classification for one supplied point in
the node #115 fee calculation. The selected source component and packet were
absent at baseline `05bc2de303c05525b71e7e257426e741bc66a390`; this contribution
does not claim a demonstrated defect in an existing production implementation.

Target: Linux x86-64 node #115, **105,896,032 bytes**, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
No captured node instructions were executed or evaluated.

The complete newly examined bodies are:

| Role | Half-open extent | Bytes | GNU rows |
|---|---|---:|---:|
| Point kernel | `0x3876290..0x3876b72` | 2,274 | 462 |
| Serial/split adapter | `0x3ebfdb0..0x3ec0251` | 1,185 | 242 |
| Overflow hook | `0x4524e40..0x4524fb1` | 369 | 83 |

These total **3 bodies / 3,828 bytes / 787 rows**. Four prior construction bodies
(`36a58d0..36a5d40`, `457cbf0..457ccac`, `41c8750..41c8ab0`,
`41cac80..41cad7e`) supply another 2,442 bytes of credited context; they are not
claimed as new exclusive coverage. The retained exports share one captured
input lineage. Full extents, CIE/FDE records, selected data/relocations and
branch/conversion/saturation bindings are in [static/records.json](static/records.json).

This advances the inner numerical operation beyond the existing validator
observations in [#2153](https://github.com/lalalune/hyperliquid-source/pull/2153),
[#2162](https://github.com/lalalune/hyperliquid-source/pull/2162),
[#2169](https://github.com/lalalune/hyperliquid-source/pull/2169) and
[#2176](https://github.com/lalalune/hyperliquid-source/pull/2176).
The FeeRateMap wire encoder in
[#2355](https://github.com/lalalune/hyperliquid-source/pull/2355) has a different
contract. Those related PRs were merged at the pre-submission readback.

## Contract and boundaries

The API accepts quantity `1..=10,000,000`, one of six exact scale encodings,
and five supplied binary64 bit patterns. Separate rounded operations, five
nonfinite-to-zero/finite-saturating conversions, signed saturating subtraction
then addition, and the final unsigned magnitude bound select the first of:
`FirstProductNegative`, `NetAndBaseNegative`, `SecondProductNegative`,
`RoundedMagnitudeAtLeastQuantity`, or `Pass`.

These labels are chosen value observations. Correspondence requires
round-to-nearest, ties-to-even, masked exceptions, gradual underflow
(DAZ=0, FTZ=0), stable valid native inputs/frame contents, and normal preserving
returns from reached overflow hooks. The library does not inspect or set FP
controls. Diagnostic bytes, hook effects, financial units, native ABI, returned
winner/state, scheduler/cancellation behavior, all-60-million-point traversal,
and the outer FMA checks remain outside this result. Quantity/scale refusals
and driver transport limits are explicit host policies.

[CONTRACT.v3.md](CONTRACT.v3.md) is the byte-exact historical authoring document.
Its “no source/model/corpus admission now” statements describe that earlier
review stage. The subsequent qualifications and source admission reported here
supersede that historical status; its mathematical premises and scope limits
remain unchanged.

## Actual qualification

Detailed identities, commands, raw evidence and chronology are recorded in
[VALIDATION.md](VALIDATION.md) and [validation/RESULTS.json](validation/RESULTS.json).

| Check | Observed result |
|---|---|
| Mathematical reference | 62 author primitive cases, 36 independent complete-class handcases and 26 independent primitive cases passed. The 36-case comparison checked final classes, not every written intermediate. |
| Pre-source corpus | Generator `23373ea37ac2dfb0891d18a57eb4fa270de74ee685927aef726a558a07c630ef` produced seven byte-identical files in two runs: 6,115 requested cases, 215 recorded duplicate aliases, **5,900 retained inputs**. Expectations were frozen before Rust source. |
| Native static checks | **56 controls** passed in normal and optimized Python runs with identical validation bytes; two GNU collector output trees were identical. Final public comment-only script edits were separately revalidated with 56 controls. |
| Source review and builds | Independent complete five-file source review reported no actionable findings. Actual offline locked metadata and debug/release builds passed; no external package dependency was introduced. |
| Rust values | Debug and release each emitted 5,900 valid rows with **zero mismatches** against the frozen mathematical expectations. Expected outputs stayed outside the child process. |
| Repeat release build | Two release driver binaries were byte-identical: `d2b363a3ddd425429a9fbd91f2c8e65365eaef3587ec927b15a3f8cdad10ac28`. This is the recorded build comparison, not a universal reproducible-build claim. |
| Linux target | The `x86_64-unknown-linux-gnu` library-only build passed. That library was not executed, and no Linux full-node or driver-link claim follows. |
| Transport | **26 release-driver controls passed**: two positive checks, including renamed IDs across all 5,900 rows and the 8,192-row limit, plus 24 malformed/refusal checks with no partial stdout. |
| Compiled semantic controls | Ten variants each built and ran in both debug and release. Every child exited zero and emitted 5,900 valid rows; each differed semantically from the frozen expectations. |

For M01 through M10, the mismatch counts were respectively
`145, 785, 416, 840, 18, 87, 147, 2, 167, 146` in **each** profile. Compile,
process and output-format failures were not counted as semantic detections.
M08's named witness is the additive A01 case
`interaction_u64_exact_wrap`: the mathematical unsigned sum is exactly `2^64`,
so saturation rejects while wrapping to zero produces `Pass`. The proof is in
[fixtures/ADDENDUM-PROOF.md](fixtures/ADDENDUM-PROOF.md); this witness is not H21.

The first static verifier attempt stopped during baseline admission because a
draft metadata anchor called the MOVABS at `0x387667a` a CMOV. The corrected
anchor is the CMOVA at `0x3876684`. The failed run and original sealed metadata
were retained; a separate amendment changed that anchor/control, and the
normal/optimized checks then passed. No numerical contract or captured bytes
were changed to obtain the result.

Finite corpus success and corruption controls do not establish exhaustive
input coverage or native runtime equivalence. The full repository test suite
was excluded because it includes captured-instruction evaluators; hosted CI
was not run. All **92 full-scope acceptance gates remain false**.

## Reproduce the bounded checks

Run from the repository root with Python 3, installed Rust 1.95.0, and the exact
hydrated node #115 input. Static scripts require the three helper hashes pinned
in [static/scope.json](static/scope.json); they fail on drift. The default static
verifier reads the capture as data and launches no decoder or captured code.
Use fresh output directories. These commands build/run only the authored
component; they do not invoke repository setup, Docker or the full test suite.

```sh
fee_root="$PWD"
fee_packet="$fee_root/research/work-items/RE-004-node115-fee-point-classifier"
fee_crate="$fee_root/src/node115-fee-point-classifier"
fee_work="$(mktemp -d "${TMPDIR:-/tmp}/fee-point-repro.XXXXXX")"

python3 -I -S -B "$fee_packet/static/verify.py" \
  --binary "$fee_root/artifacts/node/115/hl-node" --root "$fee_root" \
  --evidence "$fee_packet/static/evidence" --scope "$fee_packet/static/scope.json" \
  --scope-sha a3422d6b40792c133c53bc91d4b73ebe5e06fcd3d3d2b75a92090babc3efceef \
  --collector-sha 40fd91e920e97574f89e3f93080b4359a0865f14fb1025fbe9bf834bf5b275ef \
  --controls-sha d2dbc8f9a6abfcff3a159835f6f9b4df6a045aa74e812b5cf5b0f7aa3c69a06a \
  --out "$fee_work/static-normal"

cargo +1.95.0 metadata --offline --locked --format-version 1 \
  --manifest-path "$fee_crate/Cargo.toml"
cargo +1.95.0 build --offline --locked --manifest-path "$fee_crate/Cargo.toml" \
  --target-dir "$fee_work/build" --bin fee-point-driver
cargo +1.95.0 build --offline --locked --manifest-path "$fee_crate/Cargo.toml" \
  --target-dir "$fee_work/build" --bin fee-point-driver --release

for fee_profile in debug release; do
  fee_exe="$fee_work/build/$fee_profile/fee-point-driver"
  fee_sha="$(python3 -I -S -B -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$fee_exe")"
  python3 -I -S -B "$fee_packet/compare_rust.py" \
    --executable "$fee_exe" --sha256 "$fee_sha" --corpus "$fee_packet/corpus" \
    --manifest-sha256 c54df191f0f8b83e6816d6cc31b78e0a61c601c333f096fe7eb34bc8a4bd586b \
    --output "$fee_work/compare-$fee_profile"
done

python3 -I -S -B "$fee_packet/check_transport.py" \
  --executable "$fee_exe" --sha256 "$fee_sha" --corpus "$fee_packet/corpus" \
  --output "$fee_work/transport-release"
```

Repeat the static command with `-O` and a different fresh `--out` directory to
check optimized Python. Optional fresh disassembly through `static/collect.py`
requires the exact GNU executable pin in `scope.json`; it authenticates the
entire capture before creating a read-only input copy for three bounded exports.
It never launches the captured input.

With the trusted Linux target standard library already installed, the separate
library-only build is:

```sh
cargo +1.95.0 build --offline --locked --manifest-path "$fee_crate/Cargo.toml" \
  --target-dir "$fee_work/linux" --target x86_64-unknown-linux-gnu --lib --release
```

The comparison tool must receive the just-built reviewed driver, never a
captured binary. It verifies executable/corpus identities, sends only the
eight-field input rows to stdin, and retains complete actual output and
comparison metadata in the fresh output directory.

The packaged mutation reproducer was also actually run: all ten release
variants were detected with unchanged original inputs/tools. Its separate
record is [validation/public-reproducer.json](validation/public-reproducer.json).
It applies the exact [MUTATIONS.json](MUTATIONS.json) edits only to new source
copies, checks their identities before Cargo, and requires successful child
execution plus each named semantic mismatch. To repeat it using installed
toolchain binaries:

```sh
fee_cargo="$(rustup which --toolchain 1.95.0 cargo)"
fee_rustc="$(rustup which --toolchain 1.95.0 rustc)"
python3 -I -S -B "$fee_packet/reproduce_mutations.py" \
  --source "$fee_crate" --cargo "$fee_cargo" --rustc "$fee_rustc" \
  --comparator "$fee_packet/compare_rust.py" --corpus "$fee_packet/corpus" \
  --output "$fee_work/mutations"
```

The output must be outside Cargo workspace/config ancestry. The reproducer
uses fresh Cargo homes, offline locked builds and a clean environment; it
does not install a toolchain or package. This release-only reproduction is
separate from the original twenty debug/release variant runs above.
