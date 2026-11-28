# RE-017: Extract the selected #115 forwarded replay prefix

The [native forwarding packet](https://github.com/lalalune/hyperliquid-source/pull/7289)
establishes a normal selected wrapper at `0x581f160`. This offline adapter
extracts its unchanged nested span from an existing byte slice. It reads
the 20-byte origin and raw tag zero, uses the authenticated compact u64
reader for the length, and returns the separately bounded payload and any
remaining suffix. It does not allocate or send a message.

The verifier authenticates the Linux x86-64 node #115 binary, the writer's
FDE and the ordered origin, tag, length and span evidence. The tests use
fixed synthetic bytes. One feeds the borrowed span to the existing replay
codec and verifies the original opaque Tx bytes. Another exercises a
three-byte varint length and tests incomplete data and an unsupported tag.
The parser only recognizes the selected wrapper format. It does not model
other outer variants or determine an actual recording's origin or validity.

```sh
python3 -B research/work-items/RE-017-node115-replay-forward-extraction/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-forward-frame/Cargo.toml
cargo test --release --locked --offline --manifest-path src/node115-replay-forward-frame/Cargo.toml
cargo clippy --locked --offline --all-targets --manifest-path src/node115-replay-forward-frame/Cargo.toml -- -D warnings
```

[Raw offline output](offline-log.txt)
