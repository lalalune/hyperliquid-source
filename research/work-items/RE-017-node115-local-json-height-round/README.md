# RE-017 #115 local JSON Context height and round

Component `abci`. The selected local JSON checkpoint Context reads `height` and `round` through independent value arms. It requires height on the selected successful map return, and zeroes the separate round when that field is absent. This supplies the JSON sides of the freeze-height comparison and the source word used by the selected rewrite.

| JSON key | Static result |
| --- | --- |
| `height` | Classifies to 2. Its selected value call uses `0x1d772e0` and carries the returned word through RBP/R13 across the field loop. The presence bit at stack+0x68 is required at completion. `0x1f8ec9b` stores the word at Context output +0x28. |
| `round` or `consensus_round` | Both key comparisons reach selector 4 and share the duplicate guard. The selected value call uses the same reader and stages its word at stack+0x88. On the successful map return, a clear seen bit substitutes zero in R12. `0x1f8ec9f` stores it at Context output +0x30. |

The selected Locus caller loads the adjacent values through the SIMD lanes beginning at stack+0x358 and +0x368. [The aggregate evidence](https://github.com/lalalune/hyperliquid-source/pull/7260) traces the neighboring hardfork pair and pins the subsequent copy spans. The [rewrite evidence](../RE-017-node115-local-replay-hardfork-rewrite/README.md) distinguishes the reads of state +0x28 and state +0x30 from the other fields. The source of the two Context scalars on this JSON lane does not require an arithmetic conversion between height and round. This packet leaves real file contents and root equality open.

## Offline verification

From the repository root:

```sh
python3 -B research/work-items/RE-017-node115-local-json-height-round/verify.py
```

The verifier pins the artifact digest, FDE ranges, the two table dispatches, alias comparison bytes, shared reader and selected return instructions. See [raw output](offline-log.txt) and [witness instructions](windows.txt).
