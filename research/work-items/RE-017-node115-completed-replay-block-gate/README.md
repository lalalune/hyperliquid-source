# RE-017 #115 completed replay Block comparison

The completed replay reader now exposes an offline comparison against the ordered two-word startup input. The normal path runs the existing decoder, then projects the two words from the decoded Block parent and compares both in order. The result provides a successor only when the pair matches. It preserves an earlier decode error on the decoded prefix and distinguishes the Tx route from a Block mismatch. This is useful for joining a restored state fixture to completed replay bytes without reimplementing compression, wire decoding or the parent layout.

- [Completed buffer](../RE-017-node115-replay-completed-payload/README.md) pins the plain and compressed spans.
- [Block identity gate](../RE-017-node115-replay-block-identity-gate/README.md) pins the two ordered comparisons and the success-only successor.
- [Parent projection](../RE-017-node115-replay-parent-projection/README.md) pins the certificate layouts and saturating successor. The implementation uses this existing selector.
- [Startup rewrite](../RE-017-node115-local-replay-hardfork-rewrite/README.md) explains which state words a caller supplies for the selected local startup arm.

The focused tests feed the same Block through plaintext and LZ4 and exercise matching, first-word mismatch, second-word mismatch and swapped words. They retain the decode-failure and Tx controls. The static verification reuses the existing pinned #115 witnesses. The fixture data is synthetic. This gate does not apply a block, validate its signatures, identify the first queue slot, or calculate a root.

## Offline verification

From the repo root:

```sh
python3 -B research/work-items/RE-017-node115-completed-replay-block-gate/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

See the [raw offline run](offline-log.txt) for the observed output.
