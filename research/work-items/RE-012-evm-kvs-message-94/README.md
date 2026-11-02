# RE-012: EVM KVS message decoding and checkpoint context

Target: Linux x86-64 node94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `536bee4033075a1d18be048de249c1d6bbc2c779` (initial greeting routing).
The bounded implementation is the normal mode-1 wire/value decoder and
cumulative receive-size guard for `EvmKvsMsg`; the surrounding checkpoint initialization is supporting research.

## Implemented boundary

The existing standalone Rust component now exposes `evm_kvs::decode` with the
same `timed-stream` feature that enables its established varint dependency.
There is no new dependency or root workspace. The decoder accepts exactly two
wire selectors: 0 for an ordered vector of pairs of raw byte arrays, and 1 for
a unit message. It retains duplicate rows, empty arrays and non-UTF-8 bytes.
The public names `Batch` and `End` do not claim original Rust variant names.

`CONTRACT.md` predates implementation. The selector charges 4. A batch count
charges 8 and reserves `32 * count` with checked multiplication/addition.
Before each original pair, 32 is refunded; each array then charges 8 plus its
length before its availability check. Thus final charge can be smaller than
the admission peak. A byte length exceeding remaining input produces kind 1;
a short integer consumes only its marker. Overflow leaves the failed increment
unstored, while a non-overflowing limit failure retains its increment.

Success preserves suffix bytes and reports actual consumed/remaining lengths
and logical charge. Failure also reports the actual cursor and charge. The
native wrapper's separate consumed diagnostic is zero on failure; that does
not roll back the decoder state. Fast/slow u32/u64 marker distinctions and
nonminimal encodings follow the established target varint paths.

The target stores pairs as two boxed slices. The reconstruction also owns the
raw arrays, but does not claim native allocator, vector growth or ABI identity.
Native initial vector capacity is capped at 32,768 entries. This wire/value
projection does not reproduce that physical allocation strategy.

The separate `TransferSize` guard counts raw first-array and second-array
lengths across batches, including duplicate rows. It saturates additions and
rejects totals of **100,000,000,000 bytes or greater** after accounting for all
rows in a batch. Rejection retains the updated total. This limit excludes
framing, encoded prefixes and decoder logical charges. The native check is
`(total >> 11) > 0x2e90edc`, before applying the temporary database batch.
The pure guard does not allocate, apply or discard a native database batch;
callers must abandon a rejected transfer. Arithmetic tests seed private
counter states near the boundary; they do not allocate a 100 GB fixture.

## Native evidence

Nine decoder/helper FDEs contain 4,975 bytes of context. Twenty-four supporting
FDEs contain 43,244 bytes of context. Two hundred eighty-eight selected instructions bind
the decoder, caller and initialization links. `anchors.json` binds their full
body hashes, the u32 dispatch table, type string and relocation records;
`native-exports.json` retains the GNU/LLVM commands, versions in the build
receipt, complete listings and output hashes. These are analyzed extents, not
matched Rust bytes or component completion counts.

The caller supplies a complete frame to `0x28bcd70` at `0x2264f84`. Its
selected configuration passes a limit of `u64::MAX` and disables the wrapper's
TLS instrumentation; mode 1 is initialized inside the wrapper. The explicit
selector comparisons admit only 0 and 1. The vector helper is `0x2891ff0`,
its pair callback is `0x288ede0`, and each array uses `0x2891c30`. The caller's
checks for special `2^63+1` and `2^63+2` payload values do not add legal wire
selectors. They must not be used to invent selectors 2 and 3.

The new `verify.py` authenticates the entire target before checking selected
instructions, all retained FDE bodies, metadata and full relocation tuples.
Its fixed-layout mutation seam is explicitly unauthenticated. Tests mutate
instructions, body tails, dispatch/type metadata, string formats and relocation
records, and check instruction starts against both native exports. Static
binding checks do not establish execution equivalence.

## Supporting checkpoint findings

After initial greeting routing, the caller sends the greeting's byte vector
to a new background thread. The thread chain reaches `0x432fe50`, then
`0x405b970`, which is the buffer-side MessagePack state-wrapper decoder in
[RE-009 state-wrapper-read](../RE-009-state-wrapper-read-94/README.md).
Its required inner `exchange` value remains an incomplete reconstruction.
Failure is wrapped as the native error whose formatter says
`Abci state not deserializable`. No state-root or consensus validation is
established by successful outer decoding.

In parallel, helper `0x1585f90` builds
`<configured prefix>/hyperliquid_data/evm_db_hub_slow`; `0x24433c0` creates
its bundle ownership map with kind 2, whose formatter is `EvmState`.
The path reaches the existing
[OwnedDbDir constructor](../RE-009-owned-db-dir-guard-94/README.md).
The broader caller subsequently contains database initialization and the
`EvmKvsMsg` receive path. The retained helper context is not a reconstruction
of RocksDB opening, deletion, thread lifecycle or checkpoint installation.
These remain separate work, rather than assumptions inside the pure decoder.

The size guard precedes a batch-apply wrapper at `0x255ba40`. Native RTTI
identifies the temporary object as `rocksdb::WriteBatch`; its puts and apply
call shapes agree with the public [RocksDB C API implementation](https://github.com/facebook/rocksdb/blob/v8.1.1/db/c.cc).
This is supporting source-based identification, not exact dependency-version,
whole-library or source-build identity. The unit path's call shape agrees with
whole-range compaction. The new Rust code performs neither database operation.

The prior greeting-reply and varint packets are evidence leads and the source
of the independent varint implementation. No can1357 code or peer checker is
copied into this implementation. REA's existing connection and retained
section-header evidence remain available; its symbol-only native interface
cannot select this unsymbolized address corridor, so installed GNU/LLVM tools
supply bounded exports without new provider setup.

## Validation and remaining work

Actual commands, outcomes and source hashes are in `build-receipt.json` and
`VALIDATION.md`. The Rust tests cover raw row preservation, duplicates, every
truncation of a multi-row fixture, variable widths, invalid selectors/markers,
all short extension positions, reservation peaks, later array peaks, overflow
stores and suffixes. Compiled wrong-source controls are retained separately.
Only independently authored Rust and offline tools execute.

```sh
python3 research/work-items/RE-012-evm-kvs-message-94/verify.py
python3 -m unittest discover -s tests -p test_evm_kvs_message_evidence.py -v
cargo test --offline --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features
cargo test --offline --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release
cargo build --offline --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release --target x86_64-unknown-linux-gnu
make verify test catalogue-check reproduce
```

No progress gate or registered byte window changes. This parser is a required
piece of checkpoint synchronization, not a synchronized node. Frame-loop
integration, database writes and persistence, full `exchange` deserialization,
state validation, network compatibility and a source-built node/Docker image
remain unfinished.
