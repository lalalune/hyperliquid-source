# RE-001: map node #115 l1/books.rs:19 conditional call edge

- Component allocation: `orderbook`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/books.rs` as an embedded path. At ELF VA `0x54c911b` (file offset `0x54c811b`), `488d3d3ed5fe00` decodes as `lea rdi, [rip + 0xfed53e]`. Adding the signed displacement `16700734` to the next instruction VA `0x54c9122` yields `0x64b6660`. The decode from the start of FDE range `[0x54c8bf0, 0x54c91f4)` reaches that instruction boundary. The FDE itself is at `0x1353da0`.

At `0x64b6660` (file offset `0x64b4660`), an `R_X86_64_RELATIVE` relocation points to `0x44e6b2` in `.rodata`. The next 16 bytes, `0f00000000000000130000002f000000`, decode as a little-endian 64-bit length of 15 and two 32-bit values, 19 and 47. The string's normalized suffix matches `l1/books.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x54c8f1c` is `0x54c911b` and the fallthrough is `0x54c8f22`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r14, qword ptr [rbx + 0x3ae8]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54c8f15` | `4c3bb3e83a0000` | `cmp r14, qword ptr [rbx + 0x3ae8]` |
| `0x54c8f1c` | `0f83f9010000` | `jae 0x54c911b` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 16869128 added to `0x54c9128` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54c9122` | `ff1508670101` | `call qword ptr [rip + 0x1016708]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b6660 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x54c8bf0 --stop-address=0x54c9128 "$target"
od -An -tx1 -j 105596520 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e6b2 --stop-address=0x44e6c1 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d3fd5fe00`), re-decoding lands at `0x64b6661`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 19, column 47. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
