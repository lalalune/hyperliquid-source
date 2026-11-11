# RE-001: map node #115 l1/exchange/impl_global.rs:736 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_global.rs` as an embedded path. At ELF VA `0x2bf90ae` (file offset `0x2bf80ae`), `488d3d9b468503` decodes as `lea rdi, [rip + 0x385469b]`. Adding the signed displacement `59066011` to the next instruction VA `0x2bf90b5` yields `0x644d750`. The decode from the start of FDE range `[0x2bf8d70, 0x2bf965b)` reaches that instruction boundary. The FDE itself is at `0x1188a58`.

At `0x644d750` (file offset `0x644b750`), an `R_X86_64_RELATIVE` relocation points to `0x4308e8` in `.rodata`. The next 16 bytes, `1e00000000000000e002000064000000`, decode as a little-endian 64-bit length of 30 and two 32-bit values, 736 and 100. The string's normalized suffix matches `l1/exchange/impl_global.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2bf8fb9` is `0x2bf90ae` and the fallthrough is `0x2bf8fbf`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rax, rcx`. The recorded edge is selected when the `ja` predicate (`CF = 0 and ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2bf8fb6` | `4839c8` | `cmp rax, rcx` |
| `0x2bf8fb9` | `0f87ef000000` | `ja 0x2bf90ae` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 59664245 added to `0x2bf90bb` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2bf90b5` | `ff1575678e03` | `call qword ptr [rip + 0x38e6775]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d750 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2bf8d70 --stop-address=0x2bf90bb "$target"
od -An -tx1 -j 105166680 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4308e8 --stop-address=0x430906 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d9c468503`), re-decoding lands at `0x644d751`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 736, column 100. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
