# RE-001: map node #115 base/u.rs:163 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x1563f76` (file offset `0x1562f76`), `488d3ddba5e904` decodes as `lea rdi, [rip + 0x4e9a5db]`. Adding the signed displacement `82421211` to the next instruction VA `0x1563f7d` yields `0x63fe558`. The decode from the start of FDE range `[0x1563d10, 0x1563fb5)` reaches that instruction boundary. The FDE itself is at `0x10514f0`.

At `0x63fe558` (file offset `0x63fc558`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d00000000000000a300000011000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 163 and 17. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1563e9b` is `0x1563f76` and the fallthrough is `0x1563ea1`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rdx, -1`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1563e97` | `4883faff` | `cmp rdx, -1` |
| `0x1563e9b` | `0f84d5000000` | `je 0x1563f76` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 83342749 added to `0x1563f83` gives the relocation slot `0x64df520`. Its symbol-zero RELATIVE addend is `0x1681da0`. The target's FDE at `0xcc3294` describes `[0x1681da0, 0x1681db9)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1563f7d` | `ff159db5f704` | `call qword ptr [rip + 0x4f7b59d]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fe558 '
readelf -rW "$target" | grep -i '0*64df520 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1563d10 --stop-address=0x1563f83 "$target"
od -An -tx1 -j 104842592 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3ddca5e904`), re-decoding lands at `0x63fe559`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 163, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
