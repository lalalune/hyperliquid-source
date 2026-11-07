# RE-001: map node #115 base/production.rs:156 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/production.rs` as an embedded path. At ELF VA `0x1534a8e` (file offset `0x1533a8e`), `4c8d05838cec04` decodes as `lea r8, [rip + 0x4ec8c83]`. Adding the signed displacement `82611331` to the next instruction VA `0x1534a95` yields `0x63fd718`. The decode from the start of FDE range `[0x1534810, 0x1534ed0)` reaches that instruction boundary. The FDE itself is at `0x104e0e0`.

At `0x63fd718` (file offset `0x63fb718`), an `R_X86_64_RELATIVE` relocation points to `0x447b5a` in `.rodata`. The next 16 bytes, `16000000000000009c00000027000000`, decode as a little-endian 64-bit length of 22 and two 32-bit values, 156 and 39. The string's normalized suffix matches `base/production.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1534a06` is `0x1534a7a` and the fallthrough is `0x1534a08`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test al, al`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1534a04` | `84c0` | `test al, al` |
| `0x1534a06` | `7472` | `je 0x1534a7a` |
| `0x1534a7a` | `488b7c2438` | `mov rdi, qword ptr [rsp + 0x38]` |
| `0x1534a7f` | `488b742440` | `mov rsi, qword ptr [rsp + 0x40]` |
| `0x1534a84` | `488b542418` | `mov rdx, qword ptr [rsp + 0x18]` |
| `0x1534a89` | `488b4c2420` | `mov rcx, qword ptr [rsp + 0x20]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 83541861 added to `0x1534a9b` gives the relocation slot `0x64e0a00`. Its symbol-zero RELATIVE addend is `0x1502da0`. The target's FDE at `0x104b230` describes `[0x1502da0, 0x1502f82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1534a95` | `ff1565bffa04` | `call qword ptr [rip + 0x4fabf65]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fd718 '
readelf -rW "$target" | grep -i '0*64e0a00 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1534810 --stop-address=0x1534a9b "$target"
od -An -tx1 -j 104838944 -N 16 "$target"
objdump -s -j .rodata --start-address=0x447b5a --stop-address=0x447b70 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05848cec04`), re-decoding lands at `0x63fd719`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 156, column 39. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
