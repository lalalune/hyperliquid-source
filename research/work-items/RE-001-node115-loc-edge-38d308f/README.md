# RE-001: map node #115 l1/utils.rs:19 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/utils.rs` as an embedded path. At ELF VA `0x38d308f` (file offset `0x38d208f`), `4c8d052ab9b902` decodes as `lea r8, [rip + 0x2b9b92a]`. Adding the signed displacement `45725994` to the next instruction VA `0x38d3096` yields `0x646e9c0`. The decode from the start of FDE range `[0x38d2ef0, 0x38d30f5)` reaches that instruction boundary. The FDE itself is at `0x121e9b0`.

At `0x646e9c0` (file offset `0x646c9c0`), an `R_X86_64_RELATIVE` relocation points to `0x44ada0` in `.rodata`. The next 16 bytes, `0f00000000000000130000002a000000`, decode as a little-endian 64-bit length of 15 and two 32-bit values, 19 and 42. The string's normalized suffix matches `l1/utils.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x38d305a` is `0x38d3069` and the fallthrough is `0x38d305c`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rsi, rsi`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38d3057` | `4885f6` | `test rsi, rsi` |
| `0x38d305a` | `740d` | `je 0x38d3069` |
| `0x38d3069` | `4c89b42408010000` | `mov qword ptr [rsp + 0x108], r14` |
| `0x38d3071` | `48899c2410010000` | `mov qword ptr [rsp + 0x110], rbx` |
| `0x38d3079` | `4c89bc2418010000` | `mov qword ptr [rsp + 0x118], r15` |
| `0x38d3081` | `488d3d90e5ecfc` | `lea rdi, [rip - 0x3131a70]` |
| `0x38d3088` | `488d0da9bab902` | `lea rcx, [rip + 0x2b9baa9]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 46188023 added to `0x38d30a9` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38d3096` | `488d942408010000` | `lea rdx, [rsp + 0x108]` |
| `0x38d309e` | `be2b000000` | `mov esi, 0x2b` |
| `0x38d30a3` | `ff15f7c5c002` | `call qword ptr [rip + 0x2c0c5f7]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*646e9c0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x38d2ef0 --stop-address=0x38d30a9 "$target"
od -An -tx1 -j 105302472 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44ada0 --stop-address=0x44adaf "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d052bb9b902`), re-decoding lands at `0x646e9c1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 19, column 42. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
