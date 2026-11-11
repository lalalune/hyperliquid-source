# RE-001: map node #115 l1/book/book/mod.rs:1149 conditional call edge

- Component allocation: `orderbook`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/book/book/mod.rs` as an embedded path. At ELF VA `0x22ef44d` (file offset `0x22ee44d`), `488d3d74df1304` decodes as `lea rdi, [rip + 0x413df74]`. Adding the signed displacement `68411252` to the next instruction VA `0x22ef454` yields `0x642d3c8`. The decode from the start of FDE range `[0x22eef90, 0x22ef4b4)` reaches that instruction boundary. The FDE itself is at `0x10efa10`.

At `0x642d3c8` (file offset `0x642b3c8`), an `R_X86_64_RELATIVE` relocation points to `0x438bcf` in `.rodata`. The next 16 bytes, `17000000000000007d04000040000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 1149 and 64. The string's normalized suffix matches `l1/book/book/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x22ef0f6` is `0x22ef44d` and the fallthrough is `0x22ef0fc`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rax, qword ptr [r14 + 0x90]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x22ef0ef` | `493b8690000000` | `cmp rax, qword ptr [r14 + 0x90]` |
| `0x22ef0f6` | `0f8351030000` | `jae 0x22ef44d` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 69141462 added to `0x22ef45a` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x22ef454` | `ff15d6031f04` | `call qword ptr [rip + 0x41f03d6]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642d3c8 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x22eef90 --stop-address=0x22ef45a "$target"
od -An -tx1 -j 105034704 -N 16 "$target"
objdump -s -j .rodata --start-address=0x438bcf --stop-address=0x438be6 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d75df1304`), re-decoding lands at `0x642d3c9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 1149, column 64. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
