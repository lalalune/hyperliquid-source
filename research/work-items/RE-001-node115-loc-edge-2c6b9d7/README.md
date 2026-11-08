# RE-001: map node #115 l1/exchange/impl_trading.rs:401 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_trading.rs` as an embedded path. At ELF VA `0x2c6b9d7` (file offset `0x2c6a9d7`), `488d3dd21d7e03` decodes as `lea rdi, [rip + 0x37e1dd2]`. Adding the signed displacement `58596818` to the next instruction VA `0x2c6b9de` yields `0x644d7b0`. The decode from the start of FDE range `[0x2c6b3b0, 0x2c6bac5)` reaches that instruction boundary. The FDE itself is at `0x118dc18`.

At `0x644d7b0` (file offset `0x644b7b0`), an `R_X86_64_RELATIVE` relocation points to `0x4432c7` in `.rodata`. The next 16 bytes, `1f000000000000009101000056000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 401 and 86. The string's normalized suffix matches `l1/exchange/impl_trading.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c6b6dd` is `0x2c6b9d7` and the fallthrough is `0x2c6b6e3`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test sil, cl`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c6b6da` | `4084ce` | `test sil, cl` |
| `0x2c6b6dd` | `0f85f4020000` | `jne 0x2c6b9d7` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 59194956 added to `0x2c6b9e4` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c6b9de` | `ff154c3e8703` | `call qword ptr [rip + 0x3873e4c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d7b0 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c6b3b0 --stop-address=0x2c6b9e4 "$target"
od -An -tx1 -j 105166776 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4432c7 --stop-address=0x4432e6 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3dd31d7e03`), re-decoding lands at `0x644d7b1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 401, column 86. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
