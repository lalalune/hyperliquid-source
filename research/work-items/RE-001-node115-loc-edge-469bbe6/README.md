# RE-001: map node #115 l1/clearinghouse/position.rs:204 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/position.rs` as an embedded path. At ELF VA `0x469bbe6` (file offset `0x469abe6`), `488d3d1302df01` decodes as `lea rdi, [rip + 0x1df0213]`. Adding the signed displacement `31392275` to the next instruction VA `0x469bbed` yields `0x648be00`. The decode from the start of FDE range `[0x469b990, 0x469bc9f)` reaches that instruction boundary. The FDE itself is at `0xef33a0`.

At `0x648be00` (file offset `0x6489e00`), an `R_X86_64_RELATIVE` relocation points to `0x437e32` in `.rodata`. The next 16 bytes, `2000000000000000cc00000039000000`, decode as a little-endian 64-bit length of 32 and two 32-bit values, 204 and 57. The string's normalized suffix matches `l1/clearinghouse/position.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x469baf7` is `0x469bbe6` and the fallthrough is `0x469bafd`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rbx, rbx`. The recorded edge is selected when the `js` predicate (`SF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x469baf4` | `4885db` | `test rbx, rbx` |
| `0x469baf7` | `0f88e9000000` | `js 0x469bbe6` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 31734845 added to `0x469bbf3` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x469bbed` | `ff153d3ce401` | `call qword ptr [rip + 0x1e43c3d]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648be00 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x469b990 --stop-address=0x469bbf3 "$target"
od -An -tx1 -j 105422344 -N 16 "$target"
objdump -s -j .rodata --start-address=0x437e32 --stop-address=0x437e52 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d1402df01`), re-decoding lands at `0x648be01`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 204, column 57. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
