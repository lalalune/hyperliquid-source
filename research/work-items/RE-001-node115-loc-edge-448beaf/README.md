# RE-001: map node #115 l1/qtys/impl_ntl.rs:70 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/qtys/impl_ntl.rs` as an embedded path. At ELF VA `0x448beaf` (file offset `0x448aeaf`), `488d059afbff01` decodes as `lea rax, [rip + 0x1fffb9a]`. Adding the signed displacement `33553306` to the next instruction VA `0x448beb6` yields `0x648ba50`. The decode from the start of FDE range `[0x448bc30, 0x448c925)` reaches that instruction boundary. The FDE itself is at `0xebd268`.

At `0x648ba50` (file offset `0x6489a50`), an `R_X86_64_RELATIVE` relocation points to `0x43df4b` in `.rodata`. The next 16 bytes, `17000000000000004600000001000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 70 and 1. The string's normalized suffix matches `l1/qtys/impl_ntl.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x448bea9` is `0x448bffd` and the fallthrough is `0x448beaf`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rbp, r10`. The recorded edge is selected when the `jno` predicate (`OF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x448bea6` | `4c39d5` | `cmp rbp, r10` |
| `0x448bea9` | `0f814e010000` | `jno 0x448bffd` |

## Argument flow

The LEA writes `rax`. The trace follows full-width copies into `rsi`, tracking any intervening register writes. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 33918927 added to `0x448bed9` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x448beb6` | `48893c24` | `mov qword ptr [rsp], rdi` |
| `0x448beba` | `31ff` | `xor edi, edi` |
| `0x448bebc` | `4889742408` | `mov qword ptr [rsp + 8], rsi` |
| `0x448bec1` | `4889c6` | `mov rsi, rax` |
| `0x448bec4` | `4d89cc` | `mov r12, r9` |
| `0x448bec7` | `4c89c5` | `mov rbp, r8` |
| `0x448beca` | `4989cd` | `mov r13, rcx` |
| `0x448becd` | `4989d6` | `mov r14, rdx` |
| `0x448bed0` | `4d89df` | `mov r15, r11` |
| `0x448bed3` | `ff15cf8f0502` | `call qword ptr [rip + 0x2058fcf]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648ba50 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x448bc30 --stop-address=0x448bed9 "$target"
od -An -tx1 -j 105421400 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43df4b --stop-address=0x43df62 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d059bfbff01`), re-decoding lands at `0x648ba51`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 70, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
