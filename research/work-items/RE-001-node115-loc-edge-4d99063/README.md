# RE-001: map node #115 node/node.rs:596 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/node.rs` as an embedded path. At ELF VA `0x4d99063` (file offset `0x4d98063`), `4c8d055e3c7001` decodes as `lea r8, [rip + 0x1703c5e]`. Adding the signed displacement `24132702` to the next instruction VA `0x4d9906a` yields `0x649ccc8`. The decode from the start of FDE range `[0x4d98f80, 0x4d99158)` reaches that instruction boundary. The FDE itself is at `0x12f4768`.

At `0x649ccc8` (file offset `0x649acc8`), an `R_X86_64_RELATIVE` relocation points to `0x44aca3` in `.rodata`. The next 16 bytes, `1000000000000000540200002b000000`, decode as a little-endian 64-bit length of 16 and two 32-bit values, 596 and 43. The string's normalized suffix matches `node/node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4d99010` is `0x4d99050` and the fallthrough is `0x4d99012`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4d9900d` | `4885c0` | `test rax, rax` |
| `0x4d99010` | `753e` | `jne 0x4d99050` |
| `0x4d99050` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x4d99055` | `488d3d96e1b7fb` | `lea rdi, [rip - 0x4481e6a]` |
| `0x4d9905c` | `488d0dd53b7001` | `lea rcx, [rip + 0x1703bd5]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 24405542 added to `0x4d9907a` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4d9906a` | `488d542410` | `lea rdx, [rsp + 0x10]` |
| `0x4d9906f` | `be2b000000` | `mov esi, 0x2b` |
| `0x4d99074` | `ff1526667401` | `call qword ptr [rip + 0x1746626]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649ccc8 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4d98f80 --stop-address=0x4d9907a "$target"
od -An -tx1 -j 105491664 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44aca3 --stop-address=0x44acb3 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d055f3c7001`), re-decoding lands at `0x649ccc9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 596, column 43. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
