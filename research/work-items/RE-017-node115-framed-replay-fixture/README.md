# RE-017 · Decode a framed #115 replay capture offline

The previous [replay reader buffer](../RE-017-node115-replay-reader-buffer/README.md) and [compression handoff](../RE-017-node115-replay-compressed-input/README.md) start from a completed reader payload. The existing [RE-012 frame adapter](../RE-012-tcp-stream-frame-lz4-115/README.md) starts at the frame and returns the completed payload. This contribution identifies the same five-byte header format in the actual RE-017 reader at `0x5ab4390` and joins the adapter to the existing offline replay decoder.

The replay reader reads five bytes and byte-swaps the first word as a big-endian u32. The last byte selects the LZ4 transform exactly when equal to one. The same reader slot supplies the outer length maximum and LZ4 capacity limit. On the documented [replay initial-budget path](../RE-017-node115-replay-reader-limit-origin/README.md) this limit is 10,000,000 and the producer supplies that value to the payload decoder separately. The existing decoder reports its own bytes consumed and charged within the delivered plain or decompressed span.

`decode_framed_replay` works on an offline byte slice starting at a frame boundary. It consumes one frame and reports its total wire bytes and decoder prefix separately. The integration fixture supplies adjacent plain and compressed versions of the same synthetic Block. The compressed version declares a larger capacity than the bytes it actually decodes. Both yield the same inner consumed prefix and Block identity projection, despite their different frame lengths. A second fixture checks the plain path when the flag differs from one. The synchronous slice adapter's result describes its own API and the packet stops before any native asynchronous reader or state apply behavior.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-framed-replay-fixture/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

The [raw offline log](offline-log.txt) records the pinned ELF verifier and tests.
