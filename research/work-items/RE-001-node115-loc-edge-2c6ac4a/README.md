# RE-001: map node #115 l1/exchange/impl_trading.rs:401 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_trading.rs` as an embedded path. At ELF VA `0x2c6ac4a` (file offset `0x2c69c4a`), `488d3d5f2b7e03` decodes as `lea rdi, [rip + 0x37e2b5f]`. Adding the signed displacement `58600287` to the next instruction VA `0x2c6ac51` yields `0x644d7b0`. The decode from the start of FDE range `[0x2c6a640, 0x2c6ad6a)` reaches that instruction boundary. The FDE itself is at `0x118db70`.

At `0x644d7b0` (file offset `0x644b7b0`), an `R_X86_64_RELATIVE` relocation points to `0x4432c7` in `.rodata`. The next 16 bytes, `1f000000000000009101000056000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 401 and 86. The string's normalized suffix matches `l1/exchange/impl_trading.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c6a9e0` is `0x2c6ac4a` and the fallthrough is `0x2c6a9e6`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test sil, cl`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c6a9dd` | `4084ce` | `test sil, cl` |
| `0x2c6a9e0` | `0f8564020000` | `jne 0x2c6ac4a` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 59198425 added to `0x2c6ac57` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c6ac51` | `ff15d94b8703` | `call qword ptr [rip + 0x3874bd9]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d7b0 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c6a640 --stop-address=0x2c6ac57 "$target"
od -An -tx1 -j 105166776 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4432c7 --stop-address=0x4432e6 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d602b7e03`), re-decoding lands at `0x644d7b1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 401, column 86. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
