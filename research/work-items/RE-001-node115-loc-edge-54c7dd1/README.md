# RE-001: map node #115 l1/qtys/impl_ntl.rs:682 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/qtys/impl_ntl.rs` as an embedded path. At ELF VA `0x54c7dd1` (file offset `0x54c6dd1`), `488d3570bbfc00` decodes as `lea rsi, [rip + 0xfcbb70]`. Adding the signed displacement `16563056` to the next instruction VA `0x54c7dd8` yields `0x6493948`. The decode from the start of FDE range `[0x54c7b10, 0x54c870b)` reaches that instruction boundary. The FDE itself is at `0x1353ca4`.

At `0x6493948` (file offset `0x6491948`), an `R_X86_64_RELATIVE` relocation points to `0x43df4b` in `.rodata`. The next 16 bytes, `1700000000000000aa02000001000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 682 and 1. The string's normalized suffix matches `l1/qtys/impl_ntl.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x54c7cf5` is `0x54c7dd1` and the fallthrough is `0x54c7cfb`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r14, r14`. The recorded edge is selected when the `js` predicate (`SF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54c7cf2` | `4d85f6` | `test r14, r14` |
| `0x54c7cf5` | `0f88d6000000` | `js 0x54c7dd1` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 16896200 added to `0x54c7de0` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54c7dd8` | `31ff` | `xor edi, edi` |
| `0x54c7dda` | `ff15c8d00101` | `call qword ptr [rip + 0x101d0c8]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6493948 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x54c7b10 --stop-address=0x54c7de0 "$target"
od -An -tx1 -j 105453904 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43df4b --stop-address=0x43df62 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3571bbfc00`), re-decoding lands at `0x6493949`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 682, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
