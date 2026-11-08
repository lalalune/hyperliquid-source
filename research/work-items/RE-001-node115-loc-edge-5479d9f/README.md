# RE-001: map node #115 l1/spot_meta.rs:119 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/spot_meta.rs` as an embedded path. At ELF VA `0x5479d9f` (file offset `0x5478d9f`), `488d3d32cbff00` decodes as `lea rdi, [rip + 0xffcb32]`. Adding the signed displacement `16763698` to the next instruction VA `0x5479da6` yields `0x64768d8`. The decode from the start of FDE range `[0x5479b60, 0x5479de5)` reaches that instruction boundary. The FDE itself is at `0x1352b0c`.

At `0x64768d8` (file offset `0x64748d8`), an `R_X86_64_RELATIVE` relocation points to `0x432b6f` in `.rodata`. The next 16 bytes, `13000000000000007700000021000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 119 and 33. The string's normalized suffix matches `l1/spot_meta.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5479caf` is `0x5479d9f` and the fallthrough is `0x5479cb5`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r13, qword ptr [r15 + 0xb8]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5479ca8` | `4d3bafb8000000` | `cmp r13, qword ptr [r15 + 0xb8]` |
| `0x5479caf` | `0f83ea000000` | `jae 0x5479d9f` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 17193604 added to `0x5479dac` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5479da6` | `ff15845a0601` | `call qword ptr [rip + 0x1065a84]` |

## Callee identification

The resolved callee selects the diagnostic ``called `Option::unwrap()` on a `None` value``. Its bytes at `0x46e992` are `63616c6c656420604f7074696f6e3a3a756e77726170282960206f6e206120604e6f6e65602076616c7565`. The wrapper's RIP-relative indirect call uses slot `0x64df730`, whose RELATIVE addend is the sink at `0x1680e60`. The wrapper trace and sink FDE are recorded alongside the source-location record.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64768d8 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5479b60 --stop-address=0x5479dac "$target"
objdump -d -M intel --start-address=0x1680c10 --stop-address=0x1680c29 "$target"
objdump -s -j .rodata --start-address=0x46e992 --stop-address=0x46e9bd "$target"
readelf -rW "$target" | grep -i '0*64df730 '
od -An -tx1 -j 105335008 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b6f --stop-address=0x432b82 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d33cbff00`), re-decoding lands at `0x64768d9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 119, column 33. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
