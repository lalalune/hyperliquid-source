# RE-001: map node #115 base/lock_id.rs:98 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/lock_id.rs` as an embedded path. At ELF VA `0x4f20dd0` (file offset `0x4f1fdd0`), `488d3d11eb5701` decodes as `lea rdi, [rip + 0x157eb11]`. Adding the signed displacement `22539025` to the next instruction VA `0x4f20dd7` yields `0x649f8e8`. The decode from the start of FDE range `[0x4f207d0, 0x4f21105)` reaches that instruction boundary. The FDE itself is at `0x130b418`.

At `0x649f8e8` (file offset `0x649d8e8`), an `R_X86_64_RELATIVE` relocation points to `0x444a53` in `.rodata`. The next 16 bytes, `1300000000000000620000001b000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 98 and 27. The string's normalized suffix matches `base/lock_id.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4f20af3` is `0x4f20dd0` and the fallthrough is `0x4f20af9`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr fs:[rbp], 0`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4f20aed` | `6448837d0000` | `cmp qword ptr fs:[rbp], 0` |
| `0x4f20af3` | `0f85d7020000` | `jne 0x4f20dd0` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 22807811 added to `0x4f20ddd` gives the relocation slot `0x64e12e0`. Its symbol-zero RELATIVE addend is `0x1680b70`. The target's FDE at `0xcc2fb4` describes `[0x1680b70, 0x1680b9f)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4f20dd7` | `ff1503055c01` | `call qword ptr [rip + 0x15c0503]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649f8e8 '
readelf -rW "$target" | grep -i '0*64e12e0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4f207d0 --stop-address=0x4f20ddd "$target"
od -An -tx1 -j 105502960 -N 16 "$target"
objdump -s -j .rodata --start-address=0x444a53 --stop-address=0x444a66 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d12eb5701`), re-decoding lands at `0x649f8e9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 98, column 27. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
