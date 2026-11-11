# RE-001: map node #115 l1/clearinghouse/position_map.rs:274 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/position_map.rs` as an embedded path. At ELF VA `0x4205d82` (file offset `0x4204d82`), `488d3d0fe12702` decodes as `lea rdi, [rip + 0x227e10f]`. Adding the signed displacement `36167951` to the next instruction VA `0x4205d89` yields `0x6483e98`. The decode from the start of FDE range `[0x4205370, 0x4205dde)` reaches that instruction boundary. The FDE itself is at `0x1297168`.

At `0x6483e98` (file offset `0x6481e98`), an `R_X86_64_RELATIVE` relocation points to `0x438f46` in `.rodata`. The next 16 bytes, `2400000000000000120100003d000000`, decode as a little-endian 64-bit length of 36 and two 32-bit values, 274 and 61. The string's normalized suffix matches `l1/clearinghouse/position_map.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4205666` is `0x4205d82` and the fallthrough is `0x420566c`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `js` predicate (`SF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4205663` | `4885c0` | `test rax, rax` |
| `0x4205666` | `0f8816070000` | `js 0x4205d82` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 36543137 added to `0x4205d8f` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4205d89` | `ff15a19a2d02` | `call qword ptr [rip + 0x22d9aa1]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6483e98 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4205370 --stop-address=0x4205d8f "$target"
od -An -tx1 -j 105389728 -N 16 "$target"
objdump -s -j .rodata --start-address=0x438f46 --stop-address=0x438f6a "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d10e12702`), re-decoding lands at `0x6483e99`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 274, column 61. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
