# RE-001: map node #115 l1/exchange/impl_trading.rs:903 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_trading.rs` as an embedded path. At ELF VA `0x55730b2` (file offset `0x55720b2`), `488d3d5f74f300` decodes as `lea rdi, [rip + 0xf3745f]`. Adding the signed displacement `15955039` to the next instruction VA `0x55730b9` yields `0x64aa518`. The decode from the start of FDE range `[0x5571e70, 0x557367a)` reaches that instruction boundary. The FDE itself is at `0x1359d40`.

At `0x64aa518` (file offset `0x64a8518`), an `R_X86_64_RELATIVE` relocation points to `0x4432c7` in `.rodata`. The next 16 bytes, `1f00000000000000870300000e000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 903 and 14. The string's normalized suffix matches `l1/exchange/impl_trading.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5572d35` is `0x55730b2` and the fallthrough is `0x5572d3b`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r13, 2`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5572d31` | `4983fd02` | `cmp r13, 2` |
| `0x5572d35` | `0f8477030000` | `je 0x55730b2` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 16172913 added to `0x55730bf` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55730b9` | `ff1571c7f600` | `call qword ptr [rip + 0xf6c771]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa518 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5571e70 --stop-address=0x55730bf "$target"
od -An -tx1 -j 105547040 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4432c7 --stop-address=0x4432e6 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d6074f300`), re-decoding lands at `0x64aa519`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 903, column 14. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
