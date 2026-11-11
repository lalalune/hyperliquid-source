# RE-001: map node #115 node/hl_node.rs:493 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/hl_node.rs` as an embedded path. At ELF VA `0x564a5c2` (file offset `0x56495c2`), `4c8d05470ae600` decodes as `lea r8, [rip + 0xe60a47]`. Adding the signed displacement `15075911` to the next instruction VA `0x564a5c9` yields `0x64ab010`. The decode from the start of FDE range `[0x564a410, 0x564a676)` reaches that instruction boundary. The FDE itself is at `0x1367398`.

At `0x64ab010` (file offset `0x64a9010`), an `R_X86_64_RELATIVE` relocation points to `0x436a23` in `.rodata`. The next 16 bytes, `1300000000000000ed0100003e000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 493 and 62. The string's normalized suffix matches `node/hl_node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x564a44b` is `0x564a5a7` and the fallthrough is `0x564a451`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp byte ptr [rsp + 0x20], 1`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x564a446` | `807c242001` | `cmp byte ptr [rsp + 0x20], 1` |
| `0x564a44b` | `0f8456010000` | `je 0x564a5a7` |
| `0x564a5a7` | `0f10442428` | `movups xmm0, xmmword ptr [rsp + 0x28]` |
| `0x564a5ac` | `0f298424a0000000` | `movaps xmmword ptr [rsp + 0xa0], xmm0` |
| `0x564a5b4` | `488d3df2022efb` | `lea rdi, [rip - 0x4d1fd0e]` |
| `0x564a5bb` | `488d0dde07e600` | `lea rcx, [rip + 0xe607de]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 15290564 added to `0x564a5dc` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x564a5c9` | `488d9424a0000000` | `lea rdx, [rsp + 0xa0]` |
| `0x564a5d1` | `be1a000000` | `mov esi, 0x1a` |
| `0x564a5d6` | `ff15c450e900` | `call qword ptr [rip + 0xe950c4]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64ab010 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x564a410 --stop-address=0x564a5dc "$target"
od -An -tx1 -j 105549848 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436a23 --stop-address=0x436a36 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05480ae600`), re-decoding lands at `0x64ab011`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 493, column 62. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
