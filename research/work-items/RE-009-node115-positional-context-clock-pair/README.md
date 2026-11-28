# RE-009 #115 positional context clock pair

The selected MessagePack sequence visitor reads the sixth and seventh context elements through different wrappers. On success they occupy the same two 12-byte result ranges as the keyed `time` and `prev_time` paths in [#7226](https://github.com/lalalune/hyperliquid-source/pull/7226). These are zero-based sequence slots 5 and 6.

The existing [context reader analysis](../RE-009-abci-binary-context-115/README.md#selected-sequence-route) describes the early sequence limits through count five. This packet follows the later two clock reads, their output lanes and the next two scalar presence checks.

| Slot | Normal selected path | Output range |
| --- | --- | --- |
| 5, current time | Call at `0x30d38aa` enters the common time wrapper `0x3d4f3c0`. With tag 9 and nonzero first dword, result `+4/+8` stages at `rsp+0x100/+0x120`. | Dword at `+0x60`, qword at `+0x64`. |
| 6, previous time | Call at `0x30d38e6` enters `0x30410d0` with the cursor descriptor at `rsp+0x30`. When its remaining count is positive, it decrements the count and calls the common time decoder `0x2f6fa30`. The caller stages result `+4/+8` at `rsp+0xe4/+0x138` on tag 9 with nonzero first dword. | Dword at `+0x6c`, qword at `+0x70`. |

On the selected successful sequence completion, `0x30d3cea..0x30d3d1e` writes the pair into the staging interval `rsp+0xb0..+0xc7`. The SIMD copies at `0x30d3d44..0x30d3d58` place it at result `+0x60..+0x77`. The second clock straddles the two stores, with its first dword in the lower lane.

The visitor rejects count five at the first clock boundary. It initializes the descriptor count to total minus six, so count six exhausts the descriptor at the second clock boundary. The exhausted helper returns tag 9 with a zero first dword, which the visitor treats as absent. The subsequent wrapped scalar checks at `0x30d3941` and `0x30d3975` distinguish the next two absent positions. These four guards reach the same formatter boundary `0x2f7fe90` with explicit operands 5, 6, 7, and 8 respectively. The path to each operand assumes the previous selected slots decoded successfully.

The evidence applies to the selected normal sequence visitor. It does not demonstrate that a real checkpoint uses this encoding, a successful full restore, or root parity.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-positional-context-clock-pair/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
