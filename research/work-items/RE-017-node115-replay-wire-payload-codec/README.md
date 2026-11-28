# RE-017 #115 offline replay wire payload codec

The existing [payload-pair evidence](../RE-017-node115-replay-payload-pair/README.md) identifies the replay producer's native `ClientBlockWireOrTx` decoder and its block and Tx alternatives. This contribution makes both alternatives usable through one offline Rust API in [the existing Block decoder crate](../../../src/node115-client-block-success/README.md). The existing ClientBlocks response API continues to parse its vector and mandatory attachment lists.

| Replay wire prefix | Rust projection |
| --- | --- |
| Compact u32 0, Block, option byte 0 | Block with no attachment vector |
| Compact u32 0, Block, option byte 1, attachment vector | Block with a present vector, including an empty vector |
| Compact u32 1, length-prefixed data | Opaque Tx bytes |

All children share the reader's cursor and cumulative budget. The wrapper starts the charge at zero, exposes the consumed-prefix boundary through the remaining input, and uses the supplied limit. An offline caller modeling the selected producer can provide 10,000,000 as established by [the limit-initialization evidence](https://github.com/lalalune/hyperliquid-source/pull/7245). The crate reuses the Block, blob and attachment children already used by its ClientBlocks response decoder. The verifier checks the replay branch targets and confirms that the Tx and attachment call paths reference the same native blob helper.

The tests include locally constructed Block and Tx prefixes, the absent versus present-empty distinction, ownership of returned bytes, and the observed ordering of budget admission before blob shortfall. This codec projects the wire structure only. It leaves native ABI, signatures, scheduler behavior, file or checkpoint provenance, and state-root validation open.

## Offline verification

From the repository root run:

```sh
python3 -B research/work-items/RE-017-node115-replay-wire-payload-codec/verify.py
cargo test --locked --offline --manifest-path src/node115-client-block-success/Cargo.toml
```

See [the recorded run](offline-log.txt) and [the selected instruction bytes](windows.txt).
