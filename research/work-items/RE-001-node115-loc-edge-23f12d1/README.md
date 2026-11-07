# RE-001: map node #115 l1/book/book/impl_insert_order.rs:197 conditional call edge

- Component allocation: `orderbook`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/book/book/impl_insert_order.rs` as an embedded path. At ELF VA `0x23f12d1` (file offset `0x23f02d1`), `488d1528e60304` decodes as `lea rdx, [rip + 0x403e628]`. Adding the signed displacement `67364392` to the next instruction VA `0x23f12d8` yields `0x642f900`. The decode from the start of FDE range `[0x23f0a80, 0x23f5453)` reaches that instruction boundary. The FDE itself is at `0x1108310`.

At `0x642f900` (file offset `0x642d900`), an `R_X86_64_RELATIVE` relocation points to `0x436955` in `.rodata`. The next 16 bytes, `2500000000000000c500000011000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 197 and 17. The string's normalized suffix matches `l1/book/book/impl_insert_order.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x23f109d` is `0x23f12ca` and the fallthrough is `0x23f10a3`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp byte ptr [rsp + 0x18], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x23f1098` | `807c241800` | `cmp byte ptr [rsp + 0x18], 0` |
| `0x23f109d` | `0f8427020000` | `je 0x23f12ca` |
| `0x23f12ca` | `488d3de5c31ffe` | `lea rdi, [rip - 0x1e03c1b]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 68084813 added to `0x23f12e3` gives the relocation slot `0x64df730`. Its symbol-zero RELATIVE addend is `0x1680e60`. The target's FDE at `0xcc30e8` describes `[0x1680e60, 0x1680e72)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x23f12d8` | `be1d000000` | `mov esi, 0x1d` |
| `0x23f12dd` | `ff154de40e04` | `call qword ptr [rip + 0x40ee44d]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642f900 '
readelf -rW "$target" | grep -i '0*64df730 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x23f0a80 --stop-address=0x23f12e3 "$target"
od -An -tx1 -j 105044232 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436955 --stop-address=0x43697a "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1529e60304`), re-decoding lands at `0x642f901`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 197, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
