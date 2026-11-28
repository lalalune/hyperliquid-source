# RE-017 #115 checkpoint Context hardfork fields

In the selected MessagePack checkpoint Context visitor at `0x30d1c60`, `hardfork.version` occupies output +0x18 and `hardfork.round` occupies output +0x20. Both are normalized unsigned 64-bit values. The outer Context's separate `height` and `round` are at +0x28 and +0x30 on the selected map return.

| Boundary | Static evidence |
| --- | --- |
| Child key selection | The `hardfork` arm identified in [the Context map dispatch](../RE-009-abci-binary-context-115/field-arms.tsv) calls `0x32b03e0`. The child checks seven bytes using the overlapping literals `vers` and `sion`, and five bytes using `roun` plus `d`. Their selectors are 0 and 1 respectively. |
| Child value and return | Selected value reads at `0x32b0d07` and `0x32b0cb6` use the same unsigned reader slot. Version stages at stack+0xa0 and round at stack+0x90. When both fields are present, `0x32b128d` through `0x32b12d4` builds the tag-9 result with version at child output+8 and round at child output+16. |
| Outer map | The parent checks tag 9 and stages those two payload words independently. At `0x30d2f6a` through `0x30d2f88`, the absence of the entire `hardfork` field selects zero for both words on this completion path. The selected successful return writes the pair at `0x30d31aa` and `0x30d31ae`. |
| Outer positional form | On the successful branch with sufficient elements, slot 1 invokes the same child at `0x30d32e1`. The two-word payload flows through stack+0x150 to stack+0x68. The final return takes its first word from the high lane loaded at stack+0x60 and the second from the low lane loaded at stack+0x70. The stores at `0x30d2ed9` and `0x30d2ed5` give the same two output offsets. |

This gives the field names and omission behavior for fixtures targeting the selected checkpoint decoder. The [separate local-startup route](https://github.com/lalalune/hyperliquid-source/pull/7252) has its own visitor and requires a separate provenance check. This packet establishes no claim about a real checkpoint's values, how the replay pair is mutated before dispatch, or whether replay aligns the state root.

## Offline verification

From the repository root:

```sh
python3 -B research/work-items/RE-017-node115-checkpoint-hardfork-pair/verify.py
```

The verifier checks the full artifact digest, selected instruction bytes within their FDEs, decoded branch targets, the hardfork dispatch table entry and the integer reader relocation. The [raw output](offline-log.txt) and [instruction windows](windows.txt) are included. The verification reads the capture as data.
