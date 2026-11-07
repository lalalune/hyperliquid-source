# RE-001: map node #115 base/u.rs:388 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x1563be9` (file offset `0x1562be9`), `488d15c0a8e904` decodes as `lea rdx, [rip + 0x4e9a8c0]`. Adding the signed displacement `82421952` to the next instruction VA `0x1563bf0` yields `0x63fe4b0`. The decode from the start of FDE range `[0x1563bc0, 0x1563d10)` reaches that instruction boundary. The FDE itself is at `0x10514b8`.

At `0x63fe4b0` (file offset `0x63fc4b0`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d00000000000000840100000b000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 388 and 11. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1563bda` is `0x1563cb0` and the fallthrough is `0x1563be0`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1563bd8` | `85c0` | `test eax, eax` |
| `0x1563bda` | `0f85d0000000` | `jne 0x1563cb0` |
| `0x1563be0` | `488b3c24` | `mov rdi, qword ptr [rsp]` |
| `0x1563be4` | `488b742408` | `mov rsi, qword ptr [rsp + 8]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 83348834 added to `0x1563bf6` gives the relocation slot `0x64e0958`. Its symbol-zero RELATIVE addend is `0x1500e50`. The target's FDE at `0x104aee8` describes `[0x1500e50, 0x150128b)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1563bf0` | `ff1562cdf704` | `call qword ptr [rip + 0x4f7cd62]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fe4b0 '
readelf -rW "$target" | grep -i '0*64e0958 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1563bc0 --stop-address=0x1563bf6 "$target"
od -An -tx1 -j 104842424 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15c1a8e904`), re-decoding lands at `0x63fe4b1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 388, column 11. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
