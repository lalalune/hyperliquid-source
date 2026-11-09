# RE-001: map node #115 l1/exchange/impl_global.rs:736 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_global.rs` as an embedded path. At ELF VA `0x54dbf96` (file offset `0x54daf96`), `488d3d03e5fc00` decodes as `lea rdi, [rip + 0xfce503]`. Adding the signed displacement `16573699` to the next instruction VA `0x54dbf9d` yields `0x64aa4a0`. The decode from the start of FDE range `[0x54db9a0, 0x54dc208)` reaches that instruction boundary. The FDE itself is at `0x1354588`.

At `0x64aa4a0` (file offset `0x64a84a0`), an `R_X86_64_RELATIVE` relocation points to `0x4308e8` in `.rodata`. The next 16 bytes, `1e00000000000000e002000064000000`, decode as a little-endian 64-bit length of 30 and two 32-bit values, 736 and 100. The string's normalized suffix matches `l1/exchange/impl_global.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x54dbc01` is `0x54dbf96` and the fallthrough is `0x54dbc07`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rax, rcx`. The recorded edge is selected when the `ja` predicate (`CF = 0 and ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54dbbfe` | `4839c8` | `cmp rax, rcx` |
| `0x54dbc01` | `0f878f030000` | `ja 0x54dbf96` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 16791693 added to `0x54dbfa3` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54dbf9d` | `ff158d380001` | `call qword ptr [rip + 0x100388d]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa4a0 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x54db9a0 --stop-address=0x54dbfa3 "$target"
od -An -tx1 -j 105546920 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4308e8 --stop-address=0x430906 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d04e5fc00`), re-decoding lands at `0x64aa4a1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 736, column 100. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
