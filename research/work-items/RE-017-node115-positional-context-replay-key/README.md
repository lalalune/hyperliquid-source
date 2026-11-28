# RE-017 #115 positional Context height and round

The selected positional MessagePack Context success path reads height from zero-based slot 2 and round from slot 4. The pair reaches result `+0x28` and `+0x30`, the same coordinates as the keyed path in the [checkpoint round source packet](../RE-017-node115-checkpoint-round-source/README.md). Replay fixtures using this path need two independently supplied words.

| Slot | Read and transfer | Projection |
| --- | --- | --- |
| 2, height | The relative call slot at `0x30d381c` resolves to unsigned decoder `0x348e980`. The qword read at `0x30d3827` survives as R13 on the selected successful path. The return stages it at `rsp+0x78` via `0x30d3c8d`. | The second qword of the load from `rsp+0x70` reaches result `+0x28`. |
| 4, round | The call at `0x30d3879` enters Round decoder `0x4524ae0`. With successful tag and the following sequence boundary satisfied, the qword at `rsp+0x10` moves through RBP to `rsp+0x118` and then to `rsp+0x80`. | The first qword of the load from `rsp+0x80` reaches result `+0x30`. |

The preceding [context analysis](../RE-009-abci-binary-context-115/README.md#selected-sequence-route) established the early sequence count checks and the height word's coordinate. The new join follows the round word from its separate decoder through the later success continuation. It also shows that the `tx_index` call at `0x30d3846` supplies the two words used for the first SIMD lane instead of either replay-key word.

A count of three, four or five branches to the same formatter arm before the next selected read. Consequently, the keyed reader's missing-round default does not transfer to a five-or-fewer-element positional route. The success branch continues through the clock and subsequent fields. The selected Locus caller uses the same relative coordinates when carrying a successful Context result forward, as shown in the round source packet. This static trace does not establish a real checkpoint's encoding, an arithmetic relationship between the two fields, or root parity.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-017-node115-positional-context-replay-key/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
