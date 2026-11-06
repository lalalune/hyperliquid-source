# RE-008: node #115 selected-key stake predicate

This packet supports the dependency-free [Rust component](../../../src/node115-stake-predicate/README.md)
for the complete supplied selected-key/all-live-weight value operation. It
reconstructs actual lookup and aggregation over a stable flat ring of twenty-byte
keys and u64 weights. This is bounded reconstruction work, not a demonstrated
defect in an existing production implementation or full consensus acceptance.

Target: Linux x86-64 node #115, **105,896,032 bytes**, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository base: `05bc2de303c05525b71e7e257426e741bc66a390`.
No captured instructions were executed, emulated or evaluated.

| Complete native body | Half-open virtual-address extent | Bytes | GNU rows |
|---|---|---:|---:|
| Predicate | `0x4d3e1a0..0x4d3e30d` | 365 | 99 |
| Selected-key fold | `0x4e44c00..0x4e44e03` | 515 | 126 |
| All-weight fold | `0x4e406f0..0x4e4098d` | 669 | 155 |
| Key iterator | `0x5138730..0x5138946` | 534 | 126 |
| Flat lookup | `0x57f54e0..0x57f56ab` | 459 | 137 |

All **2,542 bytes / 643 rows** were already byte-censused. Prior
[#2472](https://github.com/lalalune/hyperliquid-source/pull/2472) establishes the
three-body saturation/predicate cluster;
[#2033](https://github.com/lalalune/hyperliquid-source/pull/2033) supplies proposer
lookup and real-key/saturating preparation context;
[#2308](https://github.com/lalalune/hyperliquid-source/pull/2308) supplies key-iterator
call context. Existing tree-next work and the analogous 32-byte RPC operation
[#2716](https://github.com/lalalune/hyperliquid-source/pull/2716) are credited in
the contract. This contribution claims conditional semantics and source, with
no new measured-byte coverage or dependency on those pending source components.

## Conditional value relation

For every supplied selected-key occurrence, perform actual unsigned twenty-byte
lookup and contribute the selected row's weight, or zero on a miss. Repeated
queries are preserved. Ordinary search selects the chosen segment's last equal
key. A wrapped view has an exception: equality with physical row zero selects
that seam row immediately, even if later equal keys carry other weights.

Saturate the selected contributions independently into `B` and every logical
live row's weight into `S`, each at `u64::MAX`. The result is the strict wide
comparison **`2*S < 3*B`**. Zero/zero and equality are false. `B <= S` is not
assumed: repeated selected occurrences can make B larger. The Rust API exposes
both sums as useful chosen observations; only the boolean corresponds to native
AL. No original struct layout or return ABI is claimed.

Native correspondence requires stable valid sorted flat storage, nonwrapping
native spans, valid frames, ordinary preserving `memcmp` comparison over twenty
bytes and a supplied sequence equal to the native key tree's complete in-order
expansion. It does not establish that arbitrary repeated sequences arose from
an original source constructor. The safe API checks Bounds before Order and
requires canonical head even for live-zero backing. The native empty route is
broader; these refusals are explicit host policy, not recovered native errors.

[native/CONTRACT.md](native/CONTRACT.md) and [native/PROOF.md](native/PROOF.md)
are the exact historical pre-source semantic documents. Their admission-pending
wording describes that earlier stage. [HOST-CONTRACT.md](HOST-CONTRACT.md) fixes
the separate library and input-only transport policy. Stable keys permit
equality; inactive rows are ignored. The source retains complete folds, while
the returned values cannot distinguish every equivalent early-stop program.

## Evidence and current qualification

The independent mathematical reference uses linear order statistics and
unbounded sums clamped after summing. Rust uses binary search and stepwise
saturating addition. The root source author reviewed the reference/manual
material: independence is distinct author and algorithm, **not blind authorship**.
The first forty [manual cases and derivations](reference/manual/) were frozen
before the reference; the full corpus was frozen before Rust source.

Actual retained results are summarized in [VALIDATION.md](VALIDATION.md):

- The private static verifier passed **68 controls** in normal and optimized
  Python, with byte-identical result files. The portable public verifier
  separately passed the same 68 controls.
- The parent-only comparator passed **90 synthetic controls**; the mathematical
  reference matched all **40** frozen manual cases.
- Two generator runs produced eight byte-identical output files: **8,026
  requests, 8,011 retained inputs and 15 duplicate aliases**. The original
  forty input/output rows are unchanged. The complete input is 5,494,944 bytes.
- Four offline locked builds passed: host debug, host release, repeated host
  release and Linux x86-64 library-only. The two release clients were identical.
- Actual host debug and release clients each matched **8,011/8,011** expected
  rows, with exit zero and empty stderr.
- Twelve fixed wrong-source variants each built and returned 8,011 valid rows
  in debug and release. All **24** runs produced semantic differences and their
  named manual witnesses; build/process/format failures were not detections.
- The original transport run passed **119/121** controls. Two I/O setups failed
  to induce the intended errors; two separately corrected setups then passed.
  The original failed results remain retained, not relabelled as 121/121.
- The public release reproducer completed **41 commands**: a baseline match
  and twelve release-variant detections. All thirteen complete value streams
  equal the corresponding earlier private release streams.

The three large corpus payloads use deterministic gzip. [corpus/STORAGE.json](corpus/STORAGE.json)
maps stored hashes to the exact uncompressed names/hashes retained by the
original corpus freeze and summary. No expected value was changed for Rust.
Alias rows are bookkeeping, not additional retained tests or independent cases.

The public native certificate has a newly constructed twelve-entry portable
freeze. [native/PORTABILITY.json](native/PORTABILITY.json) records exactly three
path-only file projections and the original/portable hashes. One export's
file-name header changes; its instruction rows and bytes do not. Historical
embedded hashes in the binding receipt/stdout still identify original records.
Only `FREEZE_SHA` and `BINDINGS_SHA` changed in the public static verifier.
Its separate successful public-layout qualification preserves that distinction
from the earlier private runs.

The public reproducer does not repeat static, generator, transport, debug or
Linux checks; those are separate actual qualifications. The [raw validation archive](validation/ARCHIVE.md) preserves actual commands,
streams and failure chronology. Repository checks passed as recorded in [VALIDATION.md](VALIDATION.md);
publication is a separate action. All **92 full-scope
gates remain false**.

## Reproduction entrypoints

Run from the repository root with reviewed installed tools and fresh output
directories. The reference and comparator do not read or execute the capture:

```sh
stake_packet=research/work-items/RE-008-node115-saturating-stake-predicate
stake_work="$(mktemp -d)"
python3 -I -B -S "$stake_packet/reference/qualify_manual.py" \
  --manual "$stake_packet/reference/manual" --output "$stake_work/manual"
python3 -I -B -S "$stake_packet/reference/generate_corpus.py" \
  --manual "$stake_packet/reference/manual" \
  --qualification "$stake_packet/reference/manual-qualification-01/result/RESULT.json" \
  --output "$stake_work/corpus"
python3 -I -B -S "$stake_packet/comparator/qualify_comparator.py" \
  --comparator "$stake_packet/comparator/compare_results.py" \
  --sha256 6c54e4539c16fc9cdf004bc52e15990d60d7b2673df9d6b5d3bbb680021b5f8e \
  --scratch "$stake_work/comparator"
```

Static verification reads the authenticated capture as data, never as a child
program. Its only output is a fresh result directory; the helper has no
subprocess or repository-module imports:

```sh
python3 -I -B -S "$stake_packet/static/verify_static.py" \
  --target artifacts/node/115/hl-node --evidence "$stake_packet/native" \
  --out "$stake_work/static" --controls
```

The public reproducer copies only the five pinned component files, verifies its
real one-package graph and builds offline/locked with direct installed Cargo
and rustc 1.95.0. Supply reviewed absolute tool paths; rustup shims are refused.
The output path must be fresh, absolute and outside repository/Cargo-config
ancestry. `--mutations` adds the twelve fixed release variants:

```sh
python3 -I -B -S "$stake_packet/reproduce.py" \
  --out "$stake_work/release" --cargo "$stake_cargo" --rustc "$stake_rustc"
python3 -I -B -S "$stake_packet/reproduce.py" \
  --out "$stake_work/mutations" --cargo "$stake_cargo" --rustc "$stake_rustc" \
  --mutations
```

The actual qualified public invocation used `--mutations`, which includes the
baseline. It completed without changing source, corpus or witnesses. The driver
takes zero arguments, reads only stdin and runs with an empty environment/cwd;
expected values stay in the parent comparator. This is not an OS filesystem
sandbox. Tool hashes establish identity, not safety of an arbitrary executable.
Failure stops the run while preserving raw streams and prior results.

Tree-map storage, original constructors, malformed native behavior, ABI, native
effects, concurrency, allocator failure, higher consensus eligibility and
whole-node equivalence remain unresolved. Linux was built only; execution used
macOS arm64. Full `make test`, hosted CI, container execution and a new
compiled-byte matching window are not claimed. The broad suite contains
captured-instruction evaluators and was not run for this bounded qualification.
