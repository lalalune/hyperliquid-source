# RE-001: map node #115 l1/perp_meta.rs:163 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/perp_meta.rs` as an embedded path. At ELF VA `0x22e5687` (file offset `0x22e4687`), `488d3d1a121904` decodes as `lea rdi, [rip + 0x419121a]`. Adding the signed displacement `68751898` to the next instruction VA `0x22e568e` yields `0x64768a8`. The decode from the start of FDE range `[0x22e5380, 0x22e5694)` reaches that instruction boundary. The FDE itself is at `0xcfa32c`.

At `0x64768a8` (file offset `0x64748a8`), an `R_X86_64_RELATIVE` relocation points to `0x437df7` in `.rodata`. The next 16 bytes, `1300000000000000a300000026000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 163 and 38. The string's normalized suffix matches `l1/perp_meta.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x22e53ce` is `0x22e5687` and the fallthrough is `0x22e53d4`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r10b, r10b`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x22e53cb` | `4584d2` | `test r10b, r10b` |
| `0x22e53ce` | `0f84b3020000` | `je 0x22e5687` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 69181852 added to `0x22e5694` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x22e568e` | `ff159ca11f04` | `call qword ptr [rip + 0x41fa19c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64768a8 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x22e5380 --stop-address=0x22e5694 "$target"
od -An -tx1 -j 105334960 -N 16 "$target"
objdump -s -j .rodata --start-address=0x437df7 --stop-address=0x437e0a "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d1b121904`), re-decoding lands at `0x64768a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 163, column 38. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
