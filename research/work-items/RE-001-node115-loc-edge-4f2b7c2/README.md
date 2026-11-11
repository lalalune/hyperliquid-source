# RE-001: map node #115 base/lock_id.rs:108 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/lock_id.rs` as an embedded path. At ELF VA `0x4f2b7c2` (file offset `0x4f2a7c2`), `488d3d07415701` decodes as `lea rdi, [rip + 0x1574107]`. Adding the signed displacement `22495495` to the next instruction VA `0x4f2b7c9` yields `0x649f8d0`. The decode from the start of FDE range `[0x4f2b1b0, 0x4f2bae5)` reaches that instruction boundary. The FDE itself is at `0x130bb08`.

At `0x649f8d0` (file offset `0x649d8d0`), an `R_X86_64_RELATIVE` relocation points to `0x444a53` in `.rodata`. The next 16 bytes, `13000000000000006c0000002b000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 108 and 43. The string's normalized suffix matches `base/lock_id.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4f2b5a3` is `0x4f2b7c2` and the fallthrough is `0x4f2b5a9`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rcx, rdx`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4f2b5a0` | `4839d1` | `cmp rcx, rdx` |
| `0x4f2b5a3` | `0f8319020000` | `jae 0x4f2b7c2` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 22763713 added to `0x4f2b7cf` gives the relocation slot `0x64e1090`. Its symbol-zero RELATIVE addend is `0x1680ba0`. The target's FDE at `0xcc2fd0` describes `[0x1680ba0, 0x1680bcf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4f2b7c9` | `ff15c1585b01` | `call qword ptr [rip + 0x15b58c1]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649f8d0 '
readelf -rW "$target" | grep -i '0*64e1090 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4f2b1b0 --stop-address=0x4f2b7cf "$target"
od -An -tx1 -j 105502936 -N 16 "$target"
objdump -s -j .rodata --start-address=0x444a53 --stop-address=0x444a66 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d08415701`), re-decoding lands at `0x649f8d1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 108, column 43. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
