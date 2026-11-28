# RE-017 #115 MessagePack checkpoint context clocks

The keyed MessagePack restore puts `exchange.locus.ctx.time` in the 12 bytes at loaded state `+0x60..+0x6b` and `exchange.locus.ctx.prev_time` in `+0x6c..+0x77`. This supplies the checkpoint-side inputs to the clock rotation in the [begin path](../RE-017-abci-preflight-result-115/README.md). The first 12-byte value is the comparison input on that path. The second is the destination for the old current clock when a later timestamp is accepted.

The [binary context packet](../RE-009-abci-binary-context-115/README.md) identifies the names and shared decoder. The [checkpoint round source packet](../RE-017-node115-checkpoint-round-source/README.md) establishes the enclosing selected restore and allocation path for the adjacent context region. This packet identifies the separate members and exact byte intervals carried by that path.

| Field | Tag-9 payload staging in reader `0x30d1c60` | Selected map result |
| --- | --- | --- |
| `time`, index 5 | `0x30d251d..0x30d252d` stages result `+4` at `rsp+0xe4` and result `+8` at `rsp+0x1a8`. The dword reloads into EBP at `0x30d2ee7`. | `0x30d31fe` writes the dword to `+0x60`. `0x30d3209` writes the qword to `+0x64`. |
| `prev_time`, index 6 | `0x30d255d..0x30d2567` stages result `+4` in R12D and result `+8` at `rsp+0x1a0`. | `0x30d320d` writes the dword to `+0x6c`. `0x30d3219` writes the qword to `+0x70`. |

The selected completion checks EBP and R12D separately at `0x30d3156` and `0x30d315e` before those stores. Both fields use decoder `0x3d4f3c0`.

The Locus child begins at `rsp+0xc70`. The clock pair is 24 contiguous bytes starting at `rsp+0xcd0`. This starts eight bytes into the SIMD load from `rsp+0xcc8` and ends at the end of the next load from `rsp+0xcd8`. Those lanes go through `+0x4b0/+0x4c0`, `+0x550/+0x560`, and `+0x3840/+0x3850`. The `0xa10`-byte copy from `+0x3810` to `+0x1c98` places the pair at `+0x1cd0`, exactly `+0x60` into the `0xba0`-byte Locus return.

The exchange visitor copies the Locus tail from `+0xb60` through `+0x1f40` to `+0x4b60`, retaining the pair at aggregate `+0x60`. The subsequent `0xba0` copies and the wrapper's prefix copy preserve that relative coordinate. The parent restore path carries it to the decoded allocation and the materializer's `0xba0` prefix copy carries it into the live layout.

This is static evidence for the selected normal keyed route and the documented copy bindings. It does not establish fixture values, startup parity, or state-root equality.

## Reproduce

From the repository root, with LLVM objdump on PATH:

```sh
python3 -B research/work-items/RE-017-node115-messagepack-context-clocks/verify.py --check
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
