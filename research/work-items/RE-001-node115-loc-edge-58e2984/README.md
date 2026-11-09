# RE-001: map node #115 l1/book/level.rs:32 conditional call edge

- Component allocation: `orderbook`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/book/level.rs` as an embedded path. At ELF VA `0x58e2984` (file offset `0x58e1984`), `4c8d057d0bbc00` decodes as `lea r8, [rip + 0xbc0b7d]`. Adding the signed displacement `12323709` to the next instruction VA `0x58e298b` yields `0x64a3508`. The decode from the start of FDE range `[0x58e1f40, 0x58e2a74)` reaches that instruction boundary. The FDE itself is at `0x13898b0`.

At `0x64a3508` (file offset `0x64a1508`), an `R_X86_64_RELATIVE` relocation points to `0x4308d3` in `.rodata`. The next 16 bytes, `14000000000000002000000036000000`, decode as a little-endian 64-bit length of 20 and two 32-bit values, 32 and 54. The string's normalized suffix matches `l1/book/level.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x58e20b6` is `0x58e2976` and the fallthrough is `0x58e20bc`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rdx, rdx`. The recorded edge is selected when the `js` predicate (`SF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x58e20b3` | `4885d2` | `test rdx, rdx` |
| `0x58e20b6` | `0f88ba080000` | `js 0x58e2976` |
| `0x58e2976` | `488d3d6ed003fb` | `lea rdi, [rip - 0x4fc2f92]` |
| `0x58e297d` | `488d0d5c0cbc00` | `lea rcx, [rip + 0xbc0c5c]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 12569861 added to `0x58e299b` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x58e298b` | `488d542417` | `lea rdx, [rsp + 0x17]` |
| `0x58e2990` | `be2b000000` | `mov esi, 0x2b` |
| `0x58e2995` | `ff1505cdbf00` | `call qword ptr [rip + 0xbfcd05]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64a3508 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x58e1f40 --stop-address=0x58e299b "$target"
od -An -tx1 -j 105518352 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4308d3 --stop-address=0x4308e7 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d057e0bbc00`), re-decoding lands at `0x64a3509`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 32, column 54. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
