# RE-001: map node #115 l1/clearinghouse/clearinghouse.rs:1639 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/clearinghouse.rs` as an embedded path. At ELF VA `0x4473bde` (file offset `0x4472bde`), `4c8d05cb7e0102` decodes as `lea r8, [rip + 0x2017ecb]`. Adding the signed displacement `33652427` to the next instruction VA `0x4473be5` yields `0x648bab0`. The decode from the start of FDE range `[0x4473440, 0x4473d07)` reaches that instruction boundary. The FDE itself is at `0x12a502c`.

At `0x648bab0` (file offset `0x6489ab0`), an `R_X86_64_RELATIVE` relocation points to `0x44f75e` in `.rodata`. The next 16 bytes, `2500000000000000670600005b000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 1639 and 91. The string's normalized suffix matches `l1/clearinghouse/clearinghouse.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4473762` is `0x4473b60` and the fallthrough is `0x4473768`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp word ptr [rsp + 0xb0], 0x1a2`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4473758` | `6681bc24b0000000a201` | `cmp word ptr [rsp + 0xb0], 0x1a2` |
| `0x4473762` | `0f85f8030000` | `jne 0x4473b60` |
| `0x4473b60` | `0f28842410010000` | `movaps xmm0, xmmword ptr [rsp + 0x110]` |
| `0x4473b68` | `0f298424e0010000` | `movaps xmmword ptr [rsp + 0x1e0], xmm0` |
| `0x4473b70` | `0f28842400010000` | `movaps xmm0, xmmword ptr [rsp + 0x100]` |
| `0x4473b78` | `0f298424d0010000` | `movaps xmmword ptr [rsp + 0x1d0], xmm0` |
| `0x4473b80` | `0f288424f0000000` | `movaps xmm0, xmmword ptr [rsp + 0xf0]` |
| `0x4473b88` | `0f298424c0010000` | `movaps xmmword ptr [rsp + 0x1c0], xmm0` |
| `0x4473b90` | `0f288424b0000000` | `movaps xmm0, xmmword ptr [rsp + 0xb0]` |
| `0x4473b98` | `0f288c24c0000000` | `movaps xmm1, xmmword ptr [rsp + 0xc0]` |
| `0x4473ba0` | `0f289424d0000000` | `movaps xmm2, xmmword ptr [rsp + 0xd0]` |
| `0x4473ba8` | `0f289c24e0000000` | `movaps xmm3, xmmword ptr [rsp + 0xe0]` |
| `0x4473bb0` | `0f299c24b0010000` | `movaps xmmword ptr [rsp + 0x1b0], xmm3` |
| `0x4473bb8` | `0f299424a0010000` | `movaps xmmword ptr [rsp + 0x1a0], xmm2` |
| `0x4473bc0` | `0f298c2490010000` | `movaps xmmword ptr [rsp + 0x190], xmm1` |
| `0x4473bc8` | `0f29842480010000` | `movaps xmmword ptr [rsp + 0x180], xmm0` |
| `0x4473bd0` | `488d3d3bf635fc` | `lea rdi, [rip - 0x3ca09c5]` |
| `0x4473bd7` | `488d0d1a8a0102` | `lea rcx, [rip + 0x2018a1a]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 33995432 added to `0x4473bf8` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4473be5` | `488d942480010000` | `lea rdx, [rsp + 0x180]` |
| `0x4473bed` | `be2b000000` | `mov esi, 0x2b` |
| `0x4473bf2` | `ff15a8ba0602` | `call qword ptr [rip + 0x206baa8]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648bab0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4473440 --stop-address=0x4473bf8 "$target"
od -An -tx1 -j 105421496 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f75e --stop-address=0x44f783 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05cc7e0102`), re-decoding lands at `0x648bab1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 1639, column 91. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
