# Retaining price rows through the existing open-interest cap decision

`src/node115-price-list-retain` reconstructs the three ordered passes at `0x366ce20`. It supplies the actual selected row inputs to the existing [cap projection](../../../src/node115-open-interest-cap/lib.rs), retains accepted rows in place, and appends the two ordered message requests for a rejection. The prior [open-interest gate packet](../RE-006-open-interest-gate-115/README.md) and [PR #3310](https://github.com/lalalune/hyperliquid-source/pull/3310) established the static layout and arithmetic. This contribution supplies the outer source and an integration witness for the cap-word observation after an overflow callback.

Target `artifacts/node/115/hl-node` has 105896032 bytes and SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Coordinates are image VAs.

* At `0x366ce44`, `0x366ced6` and `0x366cf66` the selector is 0, 1 and 2 in Spot, Mark, External order. Each 16-byte price record supplies the asset and multiplier. On rejection the remaining survivors are copied towards the beginning without changing their order; each pass writes its length before starting the next.
* The row helper `0x3d987f0` looks up the full asset key in the stored-size ring or tree. A miss gives zero. Independently, an available book uses asset modulo 10000 as an index into 0x120-byte records and loads +0x118; a missing book supplies zero. An out-of-bounds present book stops before projection. The helper passes this latter word on the stack to `0x447c620`, which rejects a negative signed value.
* At `0x447c674..0x447c690` the overflow path saves the state pointer, invokes the diagnostic, and restores that pointer. The load of +0x378 at `0x447c6af` follows that call. The host callback receives the current cap word; the established arithmetic projection consumes the subsequently observed word. Two controlled callback cases make this ordering observable. The fixture does not assert that the native diagnostic actually changes the word.
* A sentinel result keeps the price. On the formatted arm `0x3d989e1..0x3d989f7` appends the cap message; `0x3d98ab8..0x3d98ad7` appends the missing-price message before returning false. The source preserves message fields and append order. It exposes the native diagnostic calls separately from these messages.
* On a known bad book input the host stops predicate evaluation and retains its unprocessed suffix. The three native unwind copies at `0x366d16c`, `0x366d1a7` and `0x366d1e2` preserve remaining records following earlier removals. Stable retention, typed stops and logical map contents are modeled. Native allocations, final string rendering, callback failure/unwind, reachable book contents, and later outer-gate mutations are outside scope.

## Reproduction

```sh
python3 research/work-items/RE-007-node115-price-list-retain/verify.py --target artifacts/node/115/hl-node
cargo test --offline --manifest-path src/node115-price-list-retain/Cargo.toml
```

The verifier uses Capstone 5.0.7 and pyelftools on the pinned file. The Rust fixtures compare tree and physically wrapped ring lookups, misses, full-key versus modulo-index addressing, repeated and mixed successful/rejected rows across all three lists, both callback observation orders, and stop behavior after a prior removal. They call the unchanged cap projection from #3310.
