# RE-001: map node #115 db/db_hub.rs:51 conditional call edge

- Component allocation: `storage`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `db/db_hub.rs` as an embedded path. At ELF VA `0x57c5c6c` (file offset `0x57c4c6c`), `488d15ed7ccd00` decodes as `lea rdx, [rip + 0xcd7ced]`. Adding the signed displacement `13466861` to the next instruction VA `0x57c5c73` yields `0x649d960`. The decode from the start of FDE range `[0x57c58d0, 0x57c5cf0)` reaches that instruction boundary. The FDE itself is at `0x13769cc`.

At `0x649d960` (file offset `0x649b960`), an `R_X86_64_RELATIVE` relocation points to `0x4378d8` in `.rodata`. The next 16 bytes, `10000000000000003300000012000000`, decode as a little-endian 64-bit length of 16 and two 32-bit values, 51 and 18. The string's normalized suffix matches `db/db_hub.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x57c59db` is `0x57c5c65` and the fallthrough is `0x57c59e1`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x57c59d8` | `4885c0` | `test rax, rax` |
| `0x57c59db` | `0f8484020000` | `je 0x57c5c65` |
| `0x57c5c65` | `488d3da82a15fb` | `lea rdi, [rip - 0x4ead558]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 13736690 added to `0x57c5c7e` gives the relocation slot `0x64df770`. Its symbol-zero RELATIVE addend is `0x1680bd0`. The target's FDE at `0xcc2fec` describes `[0x1680bd0, 0x1680c04)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x57c5c73` | `be16000000` | `mov esi, 0x16` |
| `0x57c5c78` | `ff15f29ad100` | `call qword ptr [rip + 0xd19af2]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649d960 '
readelf -rW "$target" | grep -i '0*64df770 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x57c58d0 --stop-address=0x57c5c7e "$target"
od -An -tx1 -j 105494888 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4378d8 --stop-address=0x4378e8 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15ee7ccd00`), re-decoding lands at `0x649d961`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 51, column 18. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
