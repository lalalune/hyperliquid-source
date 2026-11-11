# RE-001: trace node #115 l1/exchange/impl_abstraction.rs diagnostic argument to a direct call

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `l1/exchange/impl_abstraction.rs` as an embedded path. At ELF VA `0x2c38289` (file offset `0x2c37289`), `4c8d0d80558103` decodes as `lea r9, [rip + 0x3815580]`. Adding the signed displacement `58807680` to the next instruction VA `0x2c38290` yields `0x644d810`. The decode from the start of FDE range `[0x2c37ee0, 0x2c38bbe)` reaches that instruction boundary. The FDE itself is at `0x118b9fc`.

At `0x644d810` (file offset `0x644b810`), an `R_X86_64_RELATIVE` relocation points to `0x438d15` in `.rodata`. The next 16 bytes, `23000000000000009701000028000000`, decode as a little-endian 64-bit length of 35 and two 32-bit values, 407 and 40. The string's normalized suffix matches `l1/exchange/impl_abstraction.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `r9`, the SysV x86-64 integer argument register 6. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -1769237 added to `0x2c38295` gives `0x2a88380`. The target's FDE at `0xd7b26c` describes `[0x2a88380, 0x2a88641)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c38290` | `e8eb00e5ff` | `call 0x2a88380` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d810 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c37ee0 --stop-address=0x2c38295 "$target"
od -An -tx1 -j 105166872 -N 16 "$target"
objdump -s -j .rodata --start-address=0x438d15 --stop-address=0x438d38 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d81558103`), re-decoding lands at `0x644d811`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 407, column 40. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
