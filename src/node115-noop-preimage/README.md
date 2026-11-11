# Node #115 Noop preimage and inner digest

This independently authored offline library completes one selected serializer
prefix and joins it to the existing nonce/vault/expiry suffix. It advances
[issue #3912](https://github.com/lalalune/hyperliquid-source/issues/3912).
The component gates remain false.

`preimage(nonce, vault, expires_after)` returns the complete bytes passed by
the node #115 Noop serializer to its inner digest updater. The exact map prefix
is `81 a4 74 79 70 65 a4 6e 6f 6f 70`, representing `{"type":"noop"}`.
It is followed by eight big-endian nonce bytes, a vault presence byte and
optional 20-byte value, then an optional zero marker and eight big-endian
expiry bytes. Valid typed inputs produce exactly 20, 29, 40 or 49 bytes.
Present zero-valued fields remain distinct from absent fields.

`inner_digest(&preimage)` composes the proved short-input absorption and
finalization with the unchanged existing MIT permutation implementation at
`src/node115-sponge-permutation/lib.rs`. Every constructible input fits in one
136-byte block: domain byte 1 follows the input, the final padding bit is at
byte 135, and the first 32 bytes after one permutation are returned. The small
adapter manifest builds that existing source as a crate without copying it.
Its SHA-256 is pinned by the evidence verifier.

This models successful normal helper returns and valid source fields. It is
not an action decoder, general streaming hash, outer signing-domain hash,
signature, nonce provider, authorization policy or live request. The raw native
Noop action tag `0x86` is not asserted to be a wire discriminant. No private
key or captured target code is used.

## Validation

From the repository root, using the installed Rust 1.95.0 toolchain:

```sh
cargo +1.95.0 test --offline --manifest-path src/node115-noop-preimage/Cargo.toml
cargo +1.95.0 test --offline --release --manifest-path src/node115-noop-preimage/Cargo.toml
cargo +1.95.0 clippy --offline --manifest-path src/node115-noop-preimage/Cargo.toml --all-targets -- -D warnings
python3 research/work-items/RE-001-node115-noop-preimage/compare-openssl.py
```

Four integration tests cover byte order, all optional-field shapes, absent
versus present-zero fields, and 64 retained complete digest vectors. Their
digests were independently checked using local OpenSSL 4.1.0 `KECCAK-256`.
This checks owned source against an independent library; it does not execute
the target. The [static packet](../../research/work-items/RE-001-node115-noop-preimage/README.md)
records target identity, instruction boundaries, controls and prior credit.
