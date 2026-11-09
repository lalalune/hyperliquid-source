# RE-001: map node #115 l1/exchange/impl_spot_deploy.rs:476 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_spot_deploy.rs` as an embedded path. At ELF VA `0x55cce0d` (file offset `0x55cbe0d`), `4c8d054cd7ed00` decodes as `lea r8, [rip + 0xedd74c]`. Adding the signed displacement `15587148` to the next instruction VA `0x55cce14` yields `0x64aa560`. The decode from the start of FDE range `[0x55cc610, 0x55ccf5f)` reaches that instruction boundary. The FDE itself is at `0x135d7a0`.

At `0x64aa560` (file offset `0x64a8560`), an `R_X86_64_RELATIVE` relocation points to `0x4432e7` in `.rodata`. The next 16 bytes, `2300000000000000dc01000012000000`, decode as a little-endian 64-bit length of 35 and two 32-bit values, 476 and 18. The string's normalized suffix matches `l1/exchange/impl_spot_deploy.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x55cc974` is `0x55ccd9e` and the fallthrough is `0x55cc97a`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp word ptr [rsp + 0xe0], 0x1a2`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55cc96a` | `6681bc24e0000000a201` | `cmp word ptr [rsp + 0xe0], 0x1a2` |
| `0x55cc974` | `0f8524040000` | `jne 0x55ccd9e` |
| `0x55ccd9e` | `0f28842440010000` | `movaps xmm0, xmmword ptr [rsp + 0x140]` |
| `0x55ccda6` | `0f29842490000000` | `movaps xmmword ptr [rsp + 0x90], xmm0` |
| `0x55ccdae` | `0f28842430010000` | `movaps xmm0, xmmword ptr [rsp + 0x130]` |
| `0x55ccdb6` | `0f29842480000000` | `movaps xmmword ptr [rsp + 0x80], xmm0` |
| `0x55ccdbe` | `0f28842420010000` | `movaps xmm0, xmmword ptr [rsp + 0x120]` |
| `0x55ccdc6` | `0f29442470` | `movaps xmmword ptr [rsp + 0x70], xmm0` |
| `0x55ccdcb` | `0f288424e0000000` | `movaps xmm0, xmmword ptr [rsp + 0xe0]` |
| `0x55ccdd3` | `0f288c24f0000000` | `movaps xmm1, xmmword ptr [rsp + 0xf0]` |
| `0x55ccddb` | `0f28942400010000` | `movaps xmm2, xmmword ptr [rsp + 0x100]` |
| `0x55ccde3` | `0f289c2410010000` | `movaps xmm3, xmmword ptr [rsp + 0x110]` |
| `0x55ccdeb` | `0f295c2460` | `movaps xmmword ptr [rsp + 0x60], xmm3` |
| `0x55ccdf0` | `0f29542450` | `movaps xmmword ptr [rsp + 0x50], xmm2` |
| `0x55ccdf5` | `0f294c2440` | `movaps xmmword ptr [rsp + 0x40], xmm1` |
| `0x55ccdfa` | `0f29442430` | `movaps xmmword ptr [rsp + 0x30], xmm0` |
| `0x55ccdff` | `488d3d2cd935fb` | `lea rdi, [rip - 0x4ca26d4]` |
| `0x55cce06` | `488d0d33e0ed00` | `lea rcx, [rip + 0xede033]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 15804540 added to `0x55cce24` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55cce14` | `488d542430` | `lea rdx, [rsp + 0x30]` |
| `0x55cce19` | `be2b000000` | `mov esi, 0x2b` |
| `0x55cce1e` | `ff157c28f100` | `call qword ptr [rip + 0xf1287c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa560 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x55cc610 --stop-address=0x55cce24 "$target"
od -An -tx1 -j 105547112 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4432e7 --stop-address=0x44330a "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d054dd7ed00`), re-decoding lands at `0x64aa561`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 476, column 18. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
