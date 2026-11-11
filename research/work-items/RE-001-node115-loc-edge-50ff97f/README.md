# RE-001: map node #115 base/l1_map/entry.rs:60 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/l1_map/entry.rs` as an embedded path. At ELF VA `0x50ff97f` (file offset `0x50fe97f`), `488d156ad23901` decodes as `lea rdx, [rip + 0x139d26a]`. Adding the signed displacement `20566634` to the next instruction VA `0x50ff986` yields `0x649cbf0`. The decode from the start of FDE range `[0x50feba0, 0x50ffacc)` reaches that instruction boundary. The FDE itself is at `0x131e010`.

At `0x649cbf0` (file offset `0x649abf0`), an `R_X86_64_RELATIVE` relocation points to `0x4402cd` in `.rodata`. The next 16 bytes, `18000000000000003c0000000d000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 60 and 13. The string's normalized suffix matches `base/l1_map/entry.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x50ff4a0` is `0x50ff97f` and the fallthrough is `0x50ff4a6`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r14, qword ptr [rbx + 0x18]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x50ff49c` | `4c3b7318` | `cmp r14, qword ptr [rbx + 0x18]` |
| `0x50ff4a0` | `0f83d9040000` | `jae 0x50ff97f` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 20839896 added to `0x50ff998` gives the relocation slot `0x64df770`. Its symbol-zero RELATIVE addend is `0x1680bd0`. The target's FDE at `0xcc2fec` describes `[0x1680bd0, 0x1680c04)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x50ff986` | `488d3d157881fb` | `lea rdi, [rip - 0x47e87eb]` |
| `0x50ff98d` | `be14000000` | `mov esi, 0x14` |
| `0x50ff992` | `ff15d8fd3d01` | `call qword ptr [rip + 0x13dfdd8]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649cbf0 '
readelf -rW "$target" | grep -i '0*64df770 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x50feba0 --stop-address=0x50ff998 "$target"
od -An -tx1 -j 105491448 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4402cd --stop-address=0x4402e5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d156bd23901`), re-decoding lands at `0x649cbf1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 60, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
