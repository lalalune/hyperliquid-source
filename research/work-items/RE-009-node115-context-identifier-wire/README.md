# RE-009 #115 MessagePack context identifier counters

The selected keyed Context reader and the named linked-commit serializer agree on these three context offsets. The reader completes an omitted `next_twap_id` with zero, while `next_oid` and `next_lid` have individual missing-field arms.

| Key | Successful read stages at | Context output store | Named serialization |
| --- | --- | --- | --- |
| `next_oid` | `rsp+0x190` at `0x30d2c55` | `+0x38` at `0x30d31ca` | `0x4d932a0` |
| `next_lid` | `rsp+0x188` at `0x30d2cfd` | `+0x40` at `0x30d31d6` | `0x4d932c8` |
| `next_twap_id` | `rsp+0x148` at `0x30d2bad` | `+0x48` at `0x30d31e2` | `0x4d932f0` |

The [Context reader packet](../RE-009-abci-binary-context-115/README.md) and [#6663](https://github.com/lalalune/hyperliquid-source/pull/6663) establish the key selectors, unsigned decoder and required-field handler sites. Here the successful tag-9 paths move each returned word into its own temporary. The optional third value's seen flag at `rsp+0x108` is tested at `0x30d2f04`. When it is clear, `0x30d2f14` selects zero before the write back into the third temporary. The first two values branch to their missing-field paths at `0x30d316f` and `0x30d317d` before reaching the selected output stores.

The [linked-commit packet](../RE-017-abci-linked-commit-115/README.md#serialization-observations-and-conditional-models) terminates the counter trace at helper `0x4e0dd00`. That helper keeps the full word in R14. It emits the named key through `0x57cf860` when the configuration byte at `+0xb` is nonzero. On the selected successful path, it passes the word to the unsigned writer `0x57d00b0` in RDX. This connects the three offsets to the same unsigned width selection previously identified for the height field.

These are matching field coordinates in separate static read and write records. The evidence covers the selected keyed reader and named serializer only. It does not establish a captured round trip, replay equality, or the behavior of the allocator that advances any counter.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-context-identifier-wire/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
