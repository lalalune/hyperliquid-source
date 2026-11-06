# RE-008: node #115 flat RPC search and materialization

This packet supports the independently authored [Rust component](../../../src/node115-rpc-flat-materializer/README.md)
for consensus state retrieval. It reconstructs search over a supplied immutable
flat ring of 32-byte keys and the materializer's all-or-nothing value relation.
The source component and this packet are absent at base
`05bc2de303c05525b71e7e257426e741bc66a390`. This addresses the bounded RE-008
reconstruction task; it does not claim a defect in an existing production
implementation. RE-001 supplies the static address/helper bindings.

Target: Linux x86-64 node #115, **105,896,032 bytes**, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
No captured instructions were executed, emulated or evaluated.

| Complete native body | Half-open virtual-address extent | Bytes | GNU rows |
|---|---|---:|---:|
| Flat search | `0x57f5ee0..0x57f60cc` | 492 | 136 |
| Materializer | `0x50f95f0..0x50f9720` | 304 | 84 |

Their exact byte census already exists in
`RE-003-pr-integration-20261103/native-review.json`; the advance here is the
conditional semantics and source implementation, not new selected-byte coverage.
The lookup, tracing wrapper, collector and batch builder are credited context
from [#2523](https://github.com/lalalune/hyperliquid-source/pull/2523),
[#2568](https://github.com/lalalune/hyperliquid-source/pull/2568) and
[#2620](https://github.com/lalalune/hyperliquid-source/pull/2620).
The collector retains an internal prefix on a miss; this outer materializer
discards that prefix as a successful return value.

## Established conditional relation

Each physical row consists of a 32-byte key and an opaque eight-byte stored
handle. Live logical rows start at the supplied head, wrapping once within the
capacity. Search compares the complete key in unsigned byte-lexicographic order.
For ordinary hits, the selected segment's last equal key wins. A wrapped store
has a specific exception: equality with physical row zero immediately selects
that seam row. For logical keys `[A,A,A]`, capacity four and head three, the hit
is logical index one / physical index zero; a contiguous layout selects logical
index two. An absent key returns the number of live keys strictly below it.

Materialization performs actual lookups of supplied query keys, retaining order
and repeated values. Empty queries succeed with an empty vector. The first miss
returns failure rather than a successful prefix. The native failure path writes
its signed-minimum first output word **before** cleanup; the other output words
are unspecified. The Rust `Option` and index types are host interfaces, not a
native ABI reconstruction.

Correspondence requires valid stable storage and objects, sorted live keys,
nonoverflowing native layout arithmetic, ordinary `memcmp` over exactly 32
bytes, disjoint output and normally returning preserving helpers. Every reached
native reference increment must separately satisfy its normal-return premise.
An initially nonnegative count is insufficient for repeated acquisitions after
signed overflow. Synthetic stored words are never treated as reference counts
or dereferenced. The imported comparator's ordinary contract is assumed; the
capture's dynamically loaded libc implementation was not observed.

The materializer requests prefix drops and allocation release on failure.
The drop helper receives a vector-element address. Actual reclamation, native
reference counting, allocation/growth, locking, tracing, unwind and concurrency
effects remain unclosed. “All-or-nothing” describes the returned value, not
rollback of those effects.

[ROOT-RPC-CONTRACT.v3.md](ROOT-RPC-CONTRACT.v3.md) is the exact historical
pre-source contract. Its draft/admission status describes that earlier stage;
the later qualifications below supersede that status, not its premises.
The complete exports and unchanged GNU/LLVM tool-version streams are in
[native/](native/). [static/scope.json](static/scope.json) binds FDEs, CIEs,
relocations, imports, deciding instructions and prior packet identities.
[static/PORTABILITY.json](static/PORTABILITY.json) declares its five path-only
changes. No native export bytes or instruction operands were normalized.

## Independent expectations and actual validation

The reference uses linear order statistics with an explicit seam exception; it
does not replay the native binary-search loop or evaluate captured instructions.
Independent fixed handcases preceded the reference, corpus and Rust source.
Their [manual derivations](reference/MANUAL-PROOF.md) are preserved unchanged;
the historical `handcases.json` and `host-invalid-cases.json` names correspond
to `corpus/manual-handcases.json` and `corpus/manual-host-invalid.json` here.
The Rust author received the reviewed contract and transport specification,
without the reference implementation or expected corpus during authorship.

Actual results, with command/output records in [VALIDATION.md](VALIDATION.md):

- Reference qualification: 24 handcases, 64 searches, 24 materializations and
  seven invalid-input refusals passed.
- Two generator runs produced ten byte-identical files: 14,167 requested rows,
  **13,957 retained inputs** and 210 duplicate aliases. The finite corpus covers
  small sorted rings, wrap seams, duplicate choice, every key-byte position,
  unsigned/endian distinctions and materialization order/failure.
- Static binding: **115 controls** passed in normal and optimized Python;
  two complete GNU collector trees were identical. The public packet's verifier
  and collector separately reproduced those exact result trees.
- Offline locked debug, release, repeated release and Linux x86-64 library builds
  passed. Two host release executables were byte-identical. Debug and release
  each matched **13,957/13,957** frozen expected rows.
- Comparator qualification: 57 pure controls and 15 retained-process-wrapper
  controls passed. Synthetic process receipts test classification only, not
  actual Rust execution or timeout handling by the root runner.
- **80 transport controls** passed: 11 accepted inputs and 69 refusals with
  status two and empty stdout, including exact byte/record boundaries.
- Twelve deliberately wrong source variants were each built and executed in
  debug and release. All **24** returned complete, well-formed output with
  status zero, then failed by semantic value differences and their named frozen
  manual witnesses. Compiler, process or format failures were not detections.
- The packaged public reproducer separately passed: two complete corpus
  regenerations, qualification of the fixed handcases, all 13,957 driver rows,
  and a fresh release build/execution of each of the twelve source variants.
  Every variant changed its named witness; mismatch counts matched the original
  release run. The public helper does not replay the separate transport suite.

The corpus was frozen before Rust source. The three large public corpus files
use deterministic gzip containers; decompression restores the original bytes
and hashes in `corpus/manifest.json`. No expectation was changed after a source
failure. Mutation patches and exact replacement definitions preserve the
original authoring artifacts; their old manifests describe that private
authoring snapshot, not the complete inventory of this public packet.

## Reproduction

Run commands from the repository root with reviewed Python and Rust tools.
Use a fresh output directory for each invocation. The default reproduction
does not read or run the captured artifact:

```sh
rpc_packet=research/work-items/RE-008-node115-rpc-flat-materializer
rpc_work="$(mktemp -d)"
python3 -I -S -B "$rpc_packet/reproduce.py" --out "$rpc_work/reference"

cargo build --offline --locked --release \
  --manifest-path src/node115-rpc-flat-materializer/Cargo.toml \
  --target-dir "$rpc_work/target"
rpc_driver="$rpc_work/target/release/node115-rpc-flat-driver"
rpc_driver_sha="$(shasum -a 256 "$rpc_driver" | cut -d ' ' -f 1)"
python3 -I -S -B "$rpc_packet/reproduce.py" --out "$rpc_work/driver" \
  --driver "$rpc_driver" --driver-sha256 "$rpc_driver_sha"
```

The explicit driver option executes the caller-reviewed, source-built program.
A matching supplied hash verifies identity, not safety or provenance. It must
never point to the captured node. Inputs go only to stdin; expected answers
remain outside the child's arguments, environment and empty working directory.
This is not an operating-system filesystem sandbox.

The explicit mutation mode builds only the authored component and its twelve
literal source variants. Supply absolute paths and hashes of reviewed installed
Cargo and rustc executables:

```sh
python3 -I -S -B "$rpc_packet/reproduce.py" \
  --mutations --out "$rpc_work/mutations" \
  --cargo "$rpc_cargo" --cargo-sha256 "$rpc_cargo_sha" \
  --rustc "$rpc_rustc" --rustc-sha256 "$rpc_rustc_sha"
```

Static reproduction reads the authenticated capture as data and uses two
already pinned repository helpers. The GNU collector additionally requires an
explicit reviewed objdump path; see its `--help` for that argument.

```sh
python3 -I -S -B "$rpc_packet/static/verify.py" \
  --root "$PWD" --evidence "$rpc_packet/native" \
  --scope-sha256 0db2e80a9c4e323dae49ded523f2fad32a53e6239c58903d63755e52b6874d8c \
  --controls --output "$rpc_work/static"
```

These are finite authored-source/reference checks with static byte bindings.
Tree storage, mutation/eviction, key-domain identity, wire serialization, native
ABI/lifetimes/effects, concurrent state, allocation failure and whole-node
equivalence are excluded. Linux was built only; execution used macOS arm64.
All **92 full-scope acceptance gates remain false**. No compiled-byte matching
window is registered. Full `make test` and hosted CI are excluded because the
broad suite includes captured-instruction evaluators; the commit uses `[skip ci]`.
