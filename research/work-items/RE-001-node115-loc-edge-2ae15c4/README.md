# RE-001: map node #115 node/node.rs:239 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/node.rs` as an embedded path. At ELF VA `0x2ae15c4` (file offset `0x2ae05c4`), `4c8d054d659603` decodes as `lea r8, [rip + 0x396654d]`. Adding the signed displacement `60187981` to the next instruction VA `0x2ae15cb` yields `0x6447b18`. The decode from the start of FDE range `[0x2ae1360, 0x2ae1681)` reaches that instruction boundary. The FDE itself is at `0x117c350`.

At `0x6447b18` (file offset `0x6445b18`), an `R_X86_64_RELATIVE` relocation points to `0x44aca3` in `.rodata`. The next 16 bytes, `1000000000000000ef00000070000000`, decode as a little-endian 64-bit length of 16 and two 32-bit values, 239 and 112. The string's normalized suffix matches `node/node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2ae1590` is `0x2ae15ae` and the fallthrough is `0x2ae1592`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r15, r15`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ae158d` | `4d85ff` | `test r15, r15` |
| `0x2ae1590` | `751c` | `jne 0x2ae15ae` |
| `0x2ae15ae` | `4c89bc2458020000` | `mov qword ptr [rsp + 0x258], r15` |
| `0x2ae15b6` | `488d3d853fb2fd` | `lea rdi, [rip - 0x24dc07b]` |
| `0x2ae15bd` | `488d0d645e9603` | `lea rcx, [rip + 0x3965e64]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 60809410 added to `0x2ae15de` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ae15cb` | `488d942458020000` | `lea rdx, [rsp + 0x258]` |
| `0x2ae15d3` | `be2b000000` | `mov esi, 0x2b` |
| `0x2ae15d8` | `ff15c2e09f03` | `call qword ptr [rip + 0x39fe0c2]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6447b18 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2ae1360 --stop-address=0x2ae15de "$target"
od -An -tx1 -j 105143072 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44aca3 --stop-address=0x44acb3 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d054e659603`), re-decoding lands at `0x6447b19`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 239, column 112. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
