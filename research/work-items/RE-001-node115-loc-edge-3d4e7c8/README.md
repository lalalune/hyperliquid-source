# RE-001: map node #115 l1/spot_clearinghouse/cl_trait.rs:940 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/spot_clearinghouse/cl_trait.rs` as an embedded path. At ELF VA `0x3d4e7c8` (file offset `0x3d4d7c8`), `488d3df9b47202` decodes as `lea rdi, [rip + 0x272b4f9]`. Adding the signed displacement `41071865` to the next instruction VA `0x3d4e7cf` yields `0x6479cc8`. The decode from the start of FDE range `[0x3d4e560, 0x3d4e8ff)` reaches that instruction boundary. The FDE itself is at `0x125b858`.

At `0x6479cc8` (file offset `0x6477cc8`), an `R_X86_64_RELATIVE` relocation points to `0x449d41` in `.rodata`. The next 16 bytes, `2500000000000000ac03000049000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 940 and 73. The string's normalized suffix matches `l1/spot_clearinghouse/cl_trait.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x3d4e604` is `0x3d4e7c8` and the fallthrough is `0x3d4e60a`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rdx, rdx`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3d4e601` | `4885d2` | `test rdx, rdx` |
| `0x3d4e604` | `0f85be010000` | `jne 0x3d4e7c8` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 41488475 added to `0x3d4e7d5` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3d4e7cf` | `ff155b107902` | `call qword ptr [rip + 0x279105b]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6479cc8 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x3d4e560 --stop-address=0x3d4e7d5 "$target"
od -An -tx1 -j 105348304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x449d41 --stop-address=0x449d66 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3dfab47202`), re-decoding lands at `0x6479cc9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 940, column 73. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
