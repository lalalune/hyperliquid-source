# RE-009: persistent HyperEVM account-state Rust reconstruction

- **Component ID:** RE-009 storage and HyperEVM execution.
- **Target release and full SHA-256:** Linux x86-64 node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- **Source commit / reference commit:** implementation branch from upstream
  `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed can1357 reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23` was not used as implementation source.
- **Claim status:** observation for the retained key/value writer forms, selected reader rules,
  replacement order, BLAKE3 XOF length, accumulator byte order/arithmetic, and counters;
  implementation policy for strict canonical account/code decoding and commit separation;
  unresolved for the complete lattice preimage, native transactionality, and unsupported readers.
- **Scope included and excluded:** standalone Rust crate `src/node94-evm-state`, exact three table
  keys, supported value codecs, old-before-new lattice accounting, and caller-provided offline
  storage. Excludes RocksDB internals, snapshots, height keys, complete Eof, state roots, live data,
  target execution, networking, and other releases.

## Reproduce

From the repository root, without executing the captured node:

```sh
sha256sum artifacts/node/94/hl-node
make verify
for d in \
  research/work-items/RE-009-evm-kv-schema-94 \
  research/work-items/RE-009-code-value-wire-94 \
  research/work-items/RE-009-evm-replace-path-94 \
  research/work-items/RE-009-C-lthash-mechanism-94 \
  research/work-items/RE-009-D-lattice-digest-94 \
  research/work-items/RE-009-evm-state-wire-94; do
  (cd "$d" && sha256sum -c MANIFEST.sha256)
done
python3 -m unittest \
  tests.test_evm_kv_schema tests.test_code_value_wire \
  tests.test_evm_replace_path tests.test_lthash_mechanism \
  tests.test_lattice_digest tests.test_evm_state_wire94
CARGO_BUILD_JOBS=2 cargo build --locked --manifest-path src/node94-evm-state/Cargo.toml
CARGO_BUILD_JOBS=2 cargo build --release --locked --manifest-path src/node94-evm-state/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo test --locked --manifest-path src/node94-evm-state/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo test --release --locked --manifest-path src/node94-evm-state/Cargo.toml
CARGO_BUILD_JOBS=2 cargo clippy --locked --manifest-path src/node94-evm-state/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-evm-state/Cargo.toml -- --check
make verify
make test
make catalogue-check
make reproduce
```

Toolchain: repository-pinned Rust 1.94.1. Cargo is limited to two build jobs; test execution is
limited to two threads. The crate lockfile pins BLAKE3 1.8.2 and its transitive dependencies.

## Evidence

All native addresses are unrelocated ELF virtual addresses. This implementation consumes these
already retained, manifest-authenticated packets:

| Packet | Qualified claim used |
| --- | --- |
| `RE-009-evm-kv-schema-94` | table 24/25/26 prefixes, key sizes/order, account writer fields/defaults, storage endian conversion |
| `RE-009-code-value-wire-94` | four code variant names, supported writer fields/order, jump-table integer array and selected reader rules |
| `RE-009-evm-replace-path-94` | dispatcher `0x326aa40`, code replacement `0x326a6f0`, account replacement `0x326abd0`, addition helper `0x37ebb90`, old-before-new order |
| `RE-009-C-lthash-mechanism-94` | 2,048-byte BLAKE3 XOF, 1,024 big-endian u16 words, wrapping additions, saturating counters |
| `RE-009-D-lattice-digest-94` | BLAKE3 structural anchors and the separate three-lane digest function; no state-root claim |
| `RE-009-evm-state-wire-94` | snapshot `NoEvmDb` placeholder; database persistence remains separate from snapshot metadata |

The implementation uses only packet claims tied to selected target instructions. It does not copy
the unlicensed reference source. The complete entry-builder output hashed in replacement remains
unresolved, so the Rust API requires caller-supplied `VerifiedEntryBytes` from an
`EntryMaterializer`.

## Implementation and comparison

The independent crate has a real manifest and lockfile. Safe Rust is used throughout. Public types
cover addresses, slots, hashes, account records, stored-code variants, raw records, serialized keys
and values, typed errors, and lattice state. Exact retained examples are transcribed in a separate
integration test as well as focused module tests.

Corruption controls cover wrong table prefixes, exact key/value lengths, MessagePack marker
mutation, changed omission defaults, swapped account fields, storage endianness, wrong jump-table
order/capacity/tail encoding, accumulator word order, wrapping/saturating overflow, and repeated
determinism. Repository artifact verification covers the target signature; packet manifests are
SHA-256 manifests rather than signed manifests, so an "invalid manifest signature" control is not
applicable. The repository's manifest-integrity and false-summary controls remain in `make test`.

No compiled-byte comparison is claimed: this is a standalone component, not a recovered target
Cargo graph, and the target's compiler/dependency/link closure for this component is incomplete.
The prepared replacement API is limited to the observed account and code paths; it rejects storage
replacement rather than extrapolating the separate storage lattice-add evidence.

## Results and limitations

Final command results and exact test counts are recorded in the pull request rather than predicted
here. No progress gate is requested. Passing crate tests proves the implemented contract against
the retained fixtures; it does not prove a recovered state root, RocksDB transactionality, snapshot
compatibility, or whole-node identity.

The next question is the exact entry serialization consumed by the three replacement BLAKE3 paths,
followed by caller-level error propagation around the native database writer.

