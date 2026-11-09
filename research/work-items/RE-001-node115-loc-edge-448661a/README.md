# RE-001: map node #115 l1/clearinghouse/cl_trait.rs:287 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/cl_trait.rs` as an embedded path. At ELF VA `0x448661a` (file offset `0x448561a`), `4c8d05af570002` decodes as `lea r8, [rip + 0x20057af]`. Adding the signed displacement `33576879` to the next instruction VA `0x4486621` yields `0x648bdd0`. The decode from the start of FDE range `[0x44859a0, 0x448678d)` reaches that instruction boundary. The FDE itself is at `0x12a56a0`.

At `0x648bdd0` (file offset `0x6489dd0`), an `R_X86_64_RELATIVE` relocation points to `0x43bb35` in `.rodata`. The next 16 bytes, `20000000000000001f01000065000000`, decode as a little-endian 64-bit length of 32 and two 32-bit values, 287 and 101. The string's normalized suffix matches `l1/clearinghouse/cl_trait.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x448638c` is `0x448659c` and the fallthrough is `0x4486392`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp word ptr [rsp + 0x230], 0x1a2`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4486382` | `6681bc2430020000a201` | `cmp word ptr [rsp + 0x230], 0x1a2` |
| `0x448638c` | `0f850a020000` | `jne 0x448659c` |
| `0x448659c` | `0f28842490020000` | `movaps xmm0, xmmword ptr [rsp + 0x290]` |
| `0x44865a4` | `0f298424e0000000` | `movaps xmmword ptr [rsp + 0xe0], xmm0` |
| `0x44865ac` | `0f28842480020000` | `movaps xmm0, xmmword ptr [rsp + 0x280]` |
| `0x44865b4` | `0f298424d0000000` | `movaps xmmword ptr [rsp + 0xd0], xmm0` |
| `0x44865bc` | `0f28842470020000` | `movaps xmm0, xmmword ptr [rsp + 0x270]` |
| `0x44865c4` | `0f298424c0000000` | `movaps xmmword ptr [rsp + 0xc0], xmm0` |
| `0x44865cc` | `0f28842430020000` | `movaps xmm0, xmmword ptr [rsp + 0x230]` |
| `0x44865d4` | `0f288c2440020000` | `movaps xmm1, xmmword ptr [rsp + 0x240]` |
| `0x44865dc` | `0f28942450020000` | `movaps xmm2, xmmword ptr [rsp + 0x250]` |
| `0x44865e4` | `0f289c2460020000` | `movaps xmm3, xmmword ptr [rsp + 0x260]` |
| `0x44865ec` | `0f299c24b0000000` | `movaps xmmword ptr [rsp + 0xb0], xmm3` |
| `0x44865f4` | `0f299424a0000000` | `movaps xmmword ptr [rsp + 0xa0], xmm2` |
| `0x44865fc` | `0f298c2490000000` | `movaps xmmword ptr [rsp + 0x90], xmm1` |
| `0x4486604` | `0f29842480000000` | `movaps xmmword ptr [rsp + 0x80], xmm0` |
| `0x448660c` | `488d3dffcb34fc` | `lea rdi, [rip - 0x3cb3401]` |
| `0x4486613` | `488d0dde5f0002` | `lea rcx, [rip + 0x2005fde]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 33919084 added to `0x4486634` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4486621` | `488d942480000000` | `lea rdx, [rsp + 0x80]` |
| `0x4486629` | `be2b000000` | `mov esi, 0x2b` |
| `0x448662e` | `ff156c900502` | `call qword ptr [rip + 0x205906c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648bdd0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x44859a0 --stop-address=0x4486634 "$target"
od -An -tx1 -j 105422296 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43bb35 --stop-address=0x43bb55 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05b0570002`), re-decoding lands at `0x648bdd1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 287, column 101. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
