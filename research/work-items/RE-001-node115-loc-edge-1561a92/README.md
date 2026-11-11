# RE-001: map node #115 base/shell.rs:55 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/shell.rs` as an embedded path. At ELF VA `0x1561a92` (file offset `0x1560a92`), `488d350fcce904` decodes as `lea rsi, [rip + 0x4e9cc0f]`. Adding the signed displacement `82430991` to the next instruction VA `0x1561a99` yields `0x63fe6a8`. The decode from the start of FDE range `[0x1561970, 0x1561ba2)` reaches that instruction boundary. The FDE itself is at `0x105127c`.

At `0x63fe6a8` (file offset `0x63fc6a8`), an `R_X86_64_RELATIVE` relocation points to `0x449b13` in `.rodata`. The next 16 bytes, `11000000000000003700000020000000`, decode as a little-endian 64-bit length of 17 and two 32-bit values, 55 and 32. The string's normalized suffix matches `base/shell.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1561a2b` is `0x1561a8d` and the fallthrough is `0x1561a2d`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test al, cl`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1561a29` | `84c8` | `test al, cl` |
| `0x1561a2b` | `7560` | `jne 0x1561a8d` |
| `0x1561a8d` | `488b7c2428` | `mov rdi, qword ptr [rsp + 0x28]` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 83357569 added to `0x1561a9f` gives the relocation slot `0x64e0a20`. Its symbol-zero RELATIVE addend is `0x1535fd0`. The target's FDE at `0x104e31c` describes `[0x1535fd0, 0x153661e)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1561a99` | `ff1581eff704` | `call qword ptr [rip + 0x4f7ef81]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fe6a8 '
readelf -rW "$target" | grep -i '0*64e0a20 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1561970 --stop-address=0x1561a9f "$target"
od -An -tx1 -j 104842928 -N 16 "$target"
objdump -s -j .rodata --start-address=0x449b13 --stop-address=0x449b24 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3510cce904`), re-decoding lands at `0x63fe6a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 55, column 32. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
