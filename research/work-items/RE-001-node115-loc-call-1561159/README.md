# RE-001: trace node #115 base/fu.rs diagnostic argument to a direct call

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `base/fu.rs` as an embedded path. At ELF VA `0x1561159` (file offset `0x1560159`), `4c8d0d28d4e904` decodes as `lea r9, [rip + 0x4e9d428]`. Adding the signed displacement `82433064` to the next instruction VA `0x1561160` yields `0x63fe588`. The decode from the start of FDE range `[0x1560ff0, 0x156129a)` reaches that instruction boundary. The FDE itself is at `0x1051180`.

At `0x63fe588` (file offset `0x63fc588`), an `R_X86_64_RELATIVE` relocation points to `0x43caab` in `.rodata`. The next 16 bytes, `0e000000000000001102000017000000`, decode as a little-endian 64-bit length of 14 and two 32-bit values, 529 and 23. The string's normalized suffix matches `base/fu.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `r9`, the SysV x86-64 integer argument register 6. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -373205 added to `0x1561165` gives `0x1505f90`. The target's FDE at `0x104b6e8` describes `[0x1505f90, 0x1506406)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1561160` | `e82b4efaff` | `call 0x1505f90` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fe588 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1560ff0 --stop-address=0x1561165 "$target"
od -An -tx1 -j 104842640 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43caab --stop-address=0x43cab9 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d29d4e904`), re-decoding lands at `0x63fe589`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 529, column 23. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
