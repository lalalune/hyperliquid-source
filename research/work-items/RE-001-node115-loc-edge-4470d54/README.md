# RE-001: map node #115 l1/clearinghouse/clearinghouse.rs:1895 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/clearinghouse.rs` as an embedded path. At ELF VA `0x4470d54` (file offset `0x446fd54`), `4c8d0555ae0102` decodes as `lea r8, [rip + 0x201ae55]`. Adding the signed displacement `33664597` to the next instruction VA `0x4470d5b` yields `0x648bbb0`. The decode from the start of FDE range `[0x446c200, 0x4472001)` reaches that instruction boundary. The FDE itself is at `0x12a4f24`.

At `0x648bbb0` (file offset `0x6489bb0`), an `R_X86_64_RELATIVE` relocation points to `0x44f75e` in `.rodata`. The next 16 bytes, `25000000000000006707000063000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 1895 and 99. The string's normalized suffix matches `l1/clearinghouse/clearinghouse.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x446e6cf` is `0x4470cd6` and the fallthrough is `0x446e6d5`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp word ptr [rsp + 0x7a0], 0x1a2`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x446e6c5` | `6681bc24a0070000a201` | `cmp word ptr [rsp + 0x7a0], 0x1a2` |
| `0x446e6cf` | `0f8501260000` | `jne 0x4470cd6` |
| `0x4470cd6` | `0f28842400080000` | `movaps xmm0, xmmword ptr [rsp + 0x800]` |
| `0x4470cde` | `0f29842490040000` | `movaps xmmword ptr [rsp + 0x490], xmm0` |
| `0x4470ce6` | `0f288424f0070000` | `movaps xmm0, xmmword ptr [rsp + 0x7f0]` |
| `0x4470cee` | `0f29842480040000` | `movaps xmmword ptr [rsp + 0x480], xmm0` |
| `0x4470cf6` | `0f288424e0070000` | `movaps xmm0, xmmword ptr [rsp + 0x7e0]` |
| `0x4470cfe` | `0f29842470040000` | `movaps xmmword ptr [rsp + 0x470], xmm0` |
| `0x4470d06` | `0f288424a0070000` | `movaps xmm0, xmmword ptr [rsp + 0x7a0]` |
| `0x4470d0e` | `0f288c24b0070000` | `movaps xmm1, xmmword ptr [rsp + 0x7b0]` |
| `0x4470d16` | `0f289424c0070000` | `movaps xmm2, xmmword ptr [rsp + 0x7c0]` |
| `0x4470d1e` | `0f289c24d0070000` | `movaps xmm3, xmmword ptr [rsp + 0x7d0]` |
| `0x4470d26` | `0f299c2460040000` | `movaps xmmword ptr [rsp + 0x460], xmm3` |
| `0x4470d2e` | `0f29942450040000` | `movaps xmmword ptr [rsp + 0x450], xmm2` |
| `0x4470d36` | `0f298c2440040000` | `movaps xmmword ptr [rsp + 0x440], xmm1` |
| `0x4470d3e` | `0f29842430040000` | `movaps xmmword ptr [rsp + 0x430], xmm0` |
| `0x4470d46` | `488d3dc52436fc` | `lea rdi, [rip - 0x3c9db3b]` |
| `0x4470d4d` | `488d0da4b80102` | `lea rcx, [rip + 0x201b8a4]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 34007346 added to `0x4470d6e` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4470d5b` | `488d942430040000` | `lea rdx, [rsp + 0x430]` |
| `0x4470d63` | `be2b000000` | `mov esi, 0x2b` |
| `0x4470d68` | `ff1532e90602` | `call qword ptr [rip + 0x206e932]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648bbb0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x446c200 --stop-address=0x4470d6e "$target"
od -An -tx1 -j 105421752 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f75e --stop-address=0x44f783 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0556ae0102`), re-decoding lands at `0x648bbb1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 1895, column 99. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
