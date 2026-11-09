# RE-001: map node #115 l1/qtys/mod.rs:847 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/qtys/mod.rs` as an embedded path. At ELF VA `0x54e213d` (file offset `0x54e113d`), `4c8d059cf1fb00` decodes as `lea r8, [rip + 0xfbf19c]`. Adding the signed displacement `16511388` to the next instruction VA `0x54e2144` yields `0x64a12e0`. The decode from the start of FDE range `[0x54e1a00, 0x54e21a5)` reaches that instruction boundary. The FDE itself is at `0x1354978`.

At `0x64a12e0` (file offset `0x649f2e0`), an `R_X86_64_RELATIVE` relocation points to `0x435910` in `.rodata`. The next 16 bytes, `12000000000000004f03000001000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 847 and 1. The string's normalized suffix matches `l1/qtys/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x54e20c6` is `0x54e212f` and the fallthrough is `0x54e20c8`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rdx, rdx`. The recorded edge is selected when the `js` predicate (`SF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54e20c3` | `4885d2` | `test rdx, rdx` |
| `0x54e20c6` | `7867` | `js 0x54e212f` |
| `0x54e212f` | `488d3ddba143fb` | `lea rdi, [rip - 0x4bc5e25]` |
| `0x54e2136` | `488d0d93f8fb00` | `lea rcx, [rip + 0xfbf893]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 16766284 added to `0x54e2154` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54e2144` | `488d54240f` | `lea rdx, [rsp + 0xf]` |
| `0x54e2149` | `be2b000000` | `mov esi, 0x2b` |
| `0x54e214e` | `ff154cd5ff00` | `call qword ptr [rip + 0xffd54c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64a12e0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x54e1a00 --stop-address=0x54e2154 "$target"
od -An -tx1 -j 105509608 -N 16 "$target"
objdump -s -j .rodata --start-address=0x435910 --stop-address=0x435922 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d059df1fb00`), re-decoding lands at `0x64a12e1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 847, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
