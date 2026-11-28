# RE-009 · Node #115 compact and expanded raw-root capture correspondence

Both native root builders preserve the same 74 capture ordinals and 59 descriptor ordinals. For 71 captures the expanded layout's offset is exactly the compact offset plus `0xb70`. The other three are offsets `0`, `0x80`, and `0x670`, all within the first descriptor's 16-pointer group. This establishes how to normalize capture coordinates when comparing local roots from the two layouts.

| Boundary | Compact | Expanded |
| --- | --- | --- |
| Capture builder | `0x4e34ce0` | `0x4e34320` |
| Selected dispatch and status compare | `0x4e35324`, `0x4e35329` | `0x4e34964`, `0x4e34969` |
| Call to the common reducer | `0x4e35359` | `0x4e34999` |
| Digest call | `0x548db1a` | `0x548d90a` |

Both builders send the captured pointers and their 59 slots through `0x54423c0`. The descriptor for each ordinal has the same address, size, alignment, constructor, and visitor across layouts. The status-4 path reaches reducer `0x141a250` through relocation slot `0x64df500`. The two digest calls use slot `0x64e7820`, which resolves to `0x41c5140`.

The [complete capture table](capture-layouts.tsv) records both layout offsets and their shared root slot. For example, slot 13 uses compact `+0x10e8` versus expanded `+0x1c58`, and slot 26 uses compact `+0x10f8` versus expanded `+0x1c68`. The expanded interval `[+0x7c0,+0x1330)` introduces no direct capture pointer. The grouped descriptor still receives the object-base pointer, so this test does not exclude deeper visitor reads in that interval.

This is a correspondence between selected static capture and digest paths. Equivalent raw outputs still depend on restored values, intervening writes, and visitor behavior. No checkpoint or block capture was used and no observed H or H+1 root is reported.

The [compact slot packet](../RE-008-abci-hash-slots-115/README.md) and the [expanded block-root packet](../RE-017-abci-block-root-115/README.md) independently recover the two input tables. The [box-layout packet](../RE-008-abci-box-layouts-115/README.md) identifies the inserted region and sample field shifts. This check joins those observations across all capture and descriptor ordinals and anchors both normal routes to the same reducer and digest finish.

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

From repository root, with the pinned artifact present:

```sh
python3 -B research/work-items/RE-009-node115-cross-layout-root-captures/verify.py
```

The verifier decodes the two native pointer tables and descriptors again, checks the relative transfers and relocations, and matches the archived table. [Measured offline output](offline-log.txt).
