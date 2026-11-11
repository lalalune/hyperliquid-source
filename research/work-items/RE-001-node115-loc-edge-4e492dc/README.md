# RE-001: map node #115 base/u.rs:531 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x4e492dc` (file offset `0x4e482dc`), `488d151d486501` decodes as `lea rdx, [rip + 0x165481d]`. Adding the signed displacement `23414813` to the next instruction VA `0x4e492e3` yields `0x649db00`. The decode from the start of FDE range `[0x4e49110, 0x4e49488)` reaches that instruction boundary. The FDE itself is at `0x1303f38`.

At `0x649db00` (file offset `0x649bb00`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d000000000000001302000009000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 531 and 9. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4e49157` is `0x4e492b5` and the fallthrough is `0x4e4915d`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4e49154` | `4885c0` | `test rax, rax` |
| `0x4e49157` | `0f8558010000` | `jne 0x4e492b5` |
| `0x4e492b5` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x4e492ba` | `4889542418` | `mov qword ptr [rsp + 0x18], rdx` |
| `0x4e492bf` | `488d442410` | `lea rax, [rsp + 0x10]` |
| `0x4e492c4` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x4e492c9` | `488d0550d07c00` | `lea rax, [rip + 0x7cd050]` |
| `0x4e492d0` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |
| `0x4e492d5` | `488d3d7b255ffb` | `lea rdi, [rip - 0x4a0da85]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 23684042 added to `0x4e492ee` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4e492e3` | `488d742420` | `lea rsi, [rsp + 0x20]` |
| `0x4e492e8` | `ff15ca636901` | `call qword ptr [rip + 0x16963ca]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649db00 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4e49110 --stop-address=0x4e492ee "$target"
od -An -tx1 -j 105495304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d151e486501`), re-decoding lands at `0x649db01`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 531, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
