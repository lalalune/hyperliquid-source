# Preserve an existing typed checkpoint marker on retry

The reconstructed shard writer replaced the typed checkpoint marker with an empty file on every save. The native typed-marker helper returns successfully when that path already identifies a regular file. The local shard fixture now preserves a typed marker on a repeated save. Initial creation still writes an empty marker.

The selected EvmState callers format a typed marker at `0x2ad9749` and `0x2cb11cf`, then call through `0x64e09e0` into `0x1505a50`. The helper checks the regular-file predicate through `0x64e0950` at `0x1505a69`. A true result sets the success return and jumps straight to the epilogue. The false result reaches the path that can call the writer at `0x1505b37` with an empty payload. The [marker writer study](../RE-017-node115-evm-marker-writer/README.md) maps that boundary. [PR #7216](https://github.com/lalalune/hyperliquid-source/pull/7216) covers the finalized spelling. This patch applies the existing-file behavior to the reconstructed typed-marker write. It does not model a whole-directory crash transaction.

The offline regression creates a normal local EvmState checkpoint, adds a synthetic witness to the marker, and retries the same save. It verifies the exact marker bytes and reopens the checkpoint to read the expected fixture value.

## Reproduce

Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-typed-marker-retry/verify.py
cargo test --offline --locked --manifest-path src/node115-db/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-db/Cargo.toml --test typed_marker_retry
```

The [offline log](offline-log.txt) records the baseline overwrite and passing checks. The pinned executable is read as data.
