# RE-012: Node #115 `AbciStreamGreeting`, `GreetingHash`, and `EvmKvsMsg` wire protocols

Component: `transport`. Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`),
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Binary Observations

1. **`EvmKvsMsg::decode` (`0x26ff830..0x270000c`, port 3998 uncompressed)**:
   - Decodes `u32` variant tag via `0x2cd79c0` (`0x26ff91b`).
   - Variant `0` (`0x26ff931..0x26ff939`): decodes `Vec<(Box<[u8]>, Box<[u8]>)>` via `0x232c140` with element decoder `0x2cd7660`, which calls `0x232bd60` (byte vector with `u8` decoder `0x2cd7960`) twice and shrinks each allocation to exact length.
   - Variant `1` (`0x26ff93a..0x26ff950`): unit end-of-stream marker (`Done`), zero payload bytes.
   - Discriminants `>= 2` construct `DecodeError::UnexpectedVariant` naming `"EvmKvsMsg"` (`0x5f73f2` at `0x26ffaac`).

2. **`AbciStreamGreeting::decode` (`0x5821aa0..0x5821f27`, sibling `0x2ceaf00..0x2ceb298`, port 3999 uncompressed)**:
   - Decodes `u32` variant tag via `0x5821150` (`0x5821ae8`) and dispatches 6 variants (`0..=5`) via jump table `0x935bfc`.
   - Variant `0` (`0x5821b1c`): reads `blob` byte vector with Hyperliquid `bincode-fork`'s pre-allocation `InvalidBytesLength` guard (`0x5821b64..0x5821b75`), then `u64` (`0x5821db4`), then `GreetingHash` (`0x5821dd9 -> 0x582b520`).
   - Variant `1` (`0x5821b8c`): reads three `u64` varints via `0x5821250`.
   - Variants `2..=5`: unit variants (`0x5821b83`, `0x5821b7a`, `0x5821c55`, `0x5821c58`).
   - Discriminants `> 5` construct `DecodeError::UnexpectedVariant` naming `"AbciStreamGreeting"` (`0x936692` at `0x5821d27`).

3. **`GreetingHash::decode` (`0x582b520..0x582bce8`, sibling `0x2ce1dc0..0x2ce2a32`)**:
   - 3 variants (`0=Signatures`, `1=Maps`, `2=Fixed([FixedPart; 3])`), matching `src/node115-greeting-encoder` byte-for-byte; invalid discriminants reference `"GreetingHash"` (`0x936686` at `0x582b66b`).

## Implementation & Validation

Implemented in `src/net-utils/src/stream_protocols.rs` with cross-crate byte-equality tests against `node115-greeting-encoder` and uncompressed port 3998 round-trip/corruption tests in `src/net-utils/tests/stream_protocols.rs`.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_stream_protocols_115.py
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/net-runtime \
  cargo test --offline --locked --manifest-path src/net-utils/Cargo.toml
```
