# RE-001: map node #115 db/db_home.rs:85 conditional call edge

- Component allocation: `storage`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `db/db_home.rs` as an embedded path. At ELF VA `0x4469b64` (file offset `0x4468b64`), `488d15f51d0202` decodes as `lea rdx, [rip + 0x2021df5]`. Adding the signed displacement `33693173` to the next instruction VA `0x4469b6b` yields `0x648b960`. The decode from the start of FDE range `[0x44699c0, 0x4469bd8)` reaches that instruction boundary. The FDE itself is at `0x12a4d5c`.

At `0x648b960` (file offset `0x6489960`), an `R_X86_64_RELATIVE` relocation points to `0x448051` in `.rodata`. The next 16 bytes, `1100000000000000550000000d000000`, decode as a little-endian 64-bit length of 17 and two 32-bit values, 85 and 13. The string's normalized suffix matches `db/db_home.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4469b3c` is `0x4469b4c` and the fallthrough is `0x4469b3e`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r12, r12`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4469b39` | `4d85e4` | `test r12, r12` |
| `0x4469b3c` | `740e` | `je 0x4469b4c` |
| `0x4469b4c` | `48896c2410` | `mov qword ptr [rsp + 0x10], rbp` |
| `0x4469b51` | `488d0528c20700` | `lea rax, [rip + 0x7c228]` |
| `0x4469b58` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x4469b5d` | `488d3d9140fefb` | `lea rdi, [rip - 0x401bf6f]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 34036546 added to `0x4469b76` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4469b6b` | `488d742410` | `lea rsi, [rsp + 0x10]` |
| `0x4469b70` | `ff15425b0702` | `call qword ptr [rip + 0x2075b42]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b960 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x44699c0 --stop-address=0x4469b76 "$target"
od -An -tx1 -j 105421160 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448051 --stop-address=0x448062 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15f61d0202`), re-decoding lands at `0x648b961`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 85, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
