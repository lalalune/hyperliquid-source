# RE-017 #115 compact checkpoint timer projection in Rust

The compact checkpoint fixture now supplies a delay directly to the existing Rust replay timer predicate. [#7447](https://github.com/lalalune/hyperliquid-source/pull/7447) ends at the assembled bytes and the rounding correction in [#7221](https://github.com/lalalune/hyperliquid-source/pull/7221) starts with an injected scalar. `RestoredTimerDelay::from_compact_checkpoint` connects those two boundaries without changing the replay engine's eligibility or drain inputs.

The `0x42c8`-byte shape comes from the [compact materializer](../RE-016-state-materialize-3c2e860-115/README.md). The loader compares `+0x28` against the requested height in [#7390](https://github.com/lalalune/hyperliquid-source/pull/7390). The [tracker word evidence](../RE-017-node115-replay-delay-word-materialization/README.md) connects materializer input `+0x23b8` to compact `+0x3ed8`, then to the replay timer read. This adapter checks the shape and height of an already pinned local fixture, reads the word as little-endian binary64, and reuses the existing validity check, nearest-even nanosecond rounding and cap. The old scalar API and this projection share the existing saturating linear-time comparison.

From the repository root:

```sh
python3 -B research/work-items/RE-017-node115-replay-delay-word-materialization/verify.py
python3 -B research/work-items/RE-017-node115-replay-delay-rounding/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
```

The regression distinguishes the historical and compact offsets by setting two different words in one image, verifies the rounding boundary and saturating comparison, and checks wrong size, height, and invalid delay inputs. Comparison timestamps are explicit linear nanoseconds. This tests an offline projection, with no claim about native date arithmetic, loaded queue eligibility, real checkpoint completeness or root parity. No captured instructions are executed.
