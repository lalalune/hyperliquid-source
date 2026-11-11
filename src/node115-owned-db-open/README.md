# Node115 owned DB open budget

Independent `no_std` Rust for the cache-budget argument and byte-key descent
of node #115 body `0x4524660..0x4524adb`. Target SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`cache_budget` keeps only the caller's low flag bit. A clear bit yields
`0x800 << 20` (2 GiB) and ignores the value. A set bit yields `value << 30`
below `2^34` and `u64::MAX` at that boundary. `BLOCK_SIZE` is `0x4000`,
`OPTIONS_FLAG` is `1`, and `COMPANION_BYTES` is `0x08000000`. These are the
immediates this body passes to relocated setters. They are not field stores
inside those setters.

`lookup` is the unsigned byte-key scan: count at `+0x62`, keys addressed from
`+0x64`, children at `+0x70`, and a selected slot index for `[node+8+8*index]`.
Height is spent only on a descent. A null root and a height borrow are misses.
A null child is not that miss.

This is not a RocksDB open, a persistent key schema, or a snapshot version.
The sibling body `0x57c6530` uses a different default immediate. See
`research/work-items/RE-009-node115-owned-db-open-budget`.

```sh
cargo test --offline --locked --manifest-path src/node115-owned-db-open/Cargo.toml
```
