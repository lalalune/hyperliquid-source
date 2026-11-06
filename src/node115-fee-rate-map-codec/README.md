# Node115 fee-rate MessagePack codec

Independently authored, `no_std`, dependency-free source for a bounded four-value wire format. `encode_bits([u64; 4])` preserves every binary64 bit pattern in a 37-byte array4 encoding. Its implementation and existing frozen vectors are unchanged.

`decode_prefix(&[u8], depth)` adds the fresh-reader value/cursor/depth/error-category projection established for the node115 `FeeRateMapSerde` path. It handles four-element numeric arrays and the native binary-payload visitor, including malformed/truncated inputs and depth transitions. It reports safe `PanicBoundary` observations instead of executing captured panic machinery. Returned `u64` values are binary64 representations; no fee units or field meanings are assigned.

The [encoder packet](../../research/work-items/RE-005-node115-fee-rate-map-wire/README.md) retains prior credit. The [decoder packet](../../research/work-items/RE-005-node115-fee-rate-map-decode/README.md) provides complete selected native bodies, explicit premises, independently frozen expectations, source checks and reproducible static controls. Integer and binary32 conversion are constructed with integer arithmetic; the correspondence to native floating operations assumes the documented MXCSR conditions. Cached native readers, ABI layouts, diagnostic text, allocation/unwind, floating exception state and whole-node equivalence remain outside this API.

From the repository root:

```sh
cargo test --locked --offline --manifest-path src/node115-fee-rate-map-codec/Cargo.toml
cargo test --release --locked --offline --manifest-path src/node115-fee-rate-map-codec/Cargo.toml
```

The decoder tests compare 925 manual cases and 62 separately frozen scalar witnesses; the existing encoder test covers 61 vectors. These host tests do not execute captured node instructions. Linux rlib build evidence is recorded separately and is not a Linux execution claim.
