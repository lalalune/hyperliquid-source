# RE-017 #115 local hardfork pair through materialization

The selected local MessagePack restore carries the decoded `hardfork.version` and `hardfork.round` into the first materialized startup state at +0x18 and +0x20 respectively. [The local Context evidence](https://github.com/lalalune/hyperliquid-source/pull/7254) identifies the words and follows them to the enclosing Locus reader's stack +0x1810. This packet follows that pair onward through the successful aggregate returns and the local materializer call.

| Boundary | Selected transfer |
| --- | --- |
| Locus completion | `0x1ac9ee4` and `0x1ac9eec` move the pair from stack+0x1810 to +0x1830. It then moves through +0x70 and +0x580 to +0x1c88. The adjacent tail copy starts at +0x1c98, leaving both words intact. The `0xba0`-byte return copy at `0x1aca073` starts at +0x1c70, making the returned pair +0x18/+0x20. |
| Inner Exchange | The Locus child returns into stack+0xbf8. The pair at +0xc10 moves through +0x6b0 to +0x4a90. The latter is +0x18 relative to the aggregate at +0x4a78. The suffix copy begins at +0x4aa0. The later aggregate copies through +0x2cc0 and +0xbf8 preserve the pair's displacement. |
| Outer Exchange | The child result starts at stack+0x4060. The pair at +0x4078 moves through +0x80b0 to +0x9810, which is +0x18 relative to the aggregate at +0x97f8. The selected `0x27a8`-byte copies transfer that aggregate through +0x1098 to the decoder output. |
| Local reader | The allocation copy at `0x1b4511a` preserves both word offsets. The pointer saved at stack+0x38 reaches the tag-9 result's +8 and then RDX on the successful return from `0x26a3610`. |
| Local materializer | Startup preserves that pointer in R15 and uses it as the source argument to the materializer slot at `0x2cc19ea`. The selected transform copies the leading `0xba0` bytes into the constructed state. The subsequent `0x42c8`-byte copy writes the allocation returned to startup and saved in future+0xe0. |

This chain assumes the selected successful branches, the ordinary copy binding, valid non-overlapping buffers and no intervening alias writes. It ends before the [startup hardfork rewrite](../RE-017-local-state-restore-115/README.md) and the later [replay comparison](https://github.com/lalalune/hyperliquid-source/pull/7252). It establishes the initial contents of the materialized offsets on the local MessagePack route. Actual checkpoint values and state-root equality remain unverified.

## Offline verification

Run from the repository root:

```sh
python3 -B research/work-items/RE-017-node115-local-hardfork-materialization/verify.py
```

See the [raw offline run](offline-log.txt) for the authenticated artifact digest and checks, and the [instruction windows](windows.txt) for the linked addresses and copy operands. The verifier reads the ELF as data.
