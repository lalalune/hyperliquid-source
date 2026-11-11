# RE-001: map node #115 l1/spot_meta.rs:1074 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/spot_meta.rs` as an embedded path. At ELF VA `0x3c4940c` (file offset `0x3c4840c`), `488d3d05d68202` decodes as `lea rdi, [rip + 0x282d605]`. Adding the signed displacement `42128901` to the next instruction VA `0x3c49413` yields `0x6476a18`. The decode from the start of FDE range `[0x3c49360, 0x3c49433)` reaches that instruction boundary. The FDE itself is at `0xe541a0`.

At `0x6476a18` (file offset `0x6474a18`), an `R_X86_64_RELATIVE` relocation points to `0x432b6f` in `.rodata`. The next 16 bytes, `13000000000000003204000045000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 1074 and 69. The string's normalized suffix matches `l1/spot_meta.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x3c493ee` is `0x3c4940c` and the fallthrough is `0x3c493f0`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test cl, 0x10`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3c493eb` | `f6c110` | `test cl, 0x10` |
| `0x3c493ee` | `741c` | `je 0x3c4940c` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 42558487 added to `0x3c49419` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3c49413` | `ff1517648902` | `call qword ptr [rip + 0x2896417]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6476a18 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x3c49360 --stop-address=0x3c49419 "$target"
od -An -tx1 -j 105335328 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b6f --stop-address=0x432b82 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d06d68202`), re-decoding lands at `0x6476a19`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 1074, column 69. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
