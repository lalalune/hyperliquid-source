# RE-017: Feed the first decoded empty #115 Block into the ABCI fixture

The [archive/preflight field map](https://github.com/lalalune/hyperliquid-source/pull/7326) identifies the two hardfork operands. The [replay header projection](https://github.com/lalalune/hyperliquid-source/pull/7370) makes admitted header values available from a completed wire payload. The [archive header audit](https://github.com/lalalune/hyperliquid-source/pull/7568) compares those values with an independent archive row. This fixture joins the decoder and the existing ABCI pipeline through the first synthetic empty Block, reaching begin and end callbacks at the recovered checkpoint's successor height.

The probe identifies a synthetic checkpoint directory marked complete at H=42 and supplies its persisted round 40 and loader sequence 4 to the existing restore fixture. The wire payload supplies the ordinary converted Block with hardfork version 5, hardfork round 40 and admitted round 41. An independently defined archive row supplies height 43 and an empty top-level bundle descriptor. The prepared count is independently zero. The decoded Block's attachment absence is checked separately. The legacy pipeline fields named `state_time` and `block_parent_time` carry the restored and decoded hardfork words. The wire timestamp follows its own decoder path. The probe supplies `ChainName::Mainnet` through the existing typed restore-chain adapter.

The matching run consumes the entire wire input and reports the ordered begin and end callbacks at height 43, no action callback, and final modeled height/round 43/41. With only the staged second hardfork word changed to 39, the preflight returns the expected pair mismatch, calls neither callback, and preserves H=42. The checkpoint marker, archive and wire are synthetic. The test exercises reconstructed Rust. No root is injected, no action executes, and no genuine checkpoint or reference state root is claimed.

Target Linux x86-64 node #115 capture SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier reads that ELF as data and reruns the existing hardfork operand evidence. It separately pins and compiles the exact reconstructed ABCI and decoder snapshots.

## Reproduce

From the repository root, set `packet` to this directory, use Python 3.9 and Rust 1.95 or later, and make the exact [#7326 field map](https://github.com/lalalune/hyperliquid-source/pull/7326), [#7357 ABCI](https://github.com/lalalune/hyperliquid-source/pull/7357) and [#7370 decoder](https://github.com/lalalune/hyperliquid-source/pull/7370) commits available in the local Git object database.

```sh
python3 -B -u "$packet/verify.py"
```

The verifier exports the relevant Git objects to a temporary directory, runs Cargo offline with local path dependencies, and executes only the reconstructed fixture. See [the actual offline run](offline-log.txt).
