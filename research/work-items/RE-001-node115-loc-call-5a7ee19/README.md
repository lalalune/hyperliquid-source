# RE-001: trace node #115 node/consensus/network.rs diagnostic argument to a direct call

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `node/consensus/network.rs` as an embedded path. At ELF VA `0x5a7ee19` (file offset `0x5a7de19`), `488d35881ea300` decodes as `lea rsi, [rip + 0xa31e88]`. Adding the signed displacement `10690184` to the next instruction VA `0x5a7ee20` yields `0x64b0ca8`. The decode from the start of FDE range `[0x5a7e540, 0x5a7f395)` reaches that instruction boundary. The FDE itself is at `0x13aa6e0`.

At `0x64b0ca8` (file offset `0x64aeca8`), an `R_X86_64_RELATIVE` relocation points to `0x440640` in `.rodata`. The next 16 bytes, `1d00000000000000bf00000011000000`, decode as a little-endian 64-bit length of 29 and two 32-bit values, 191 and 17. The string's normalized suffix matches `node/consensus/network.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rsi`, the SysV x86-64 integer argument register 2. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 69371 added to `0x5a7ee25` gives `0x5a8fd20`. The target's FDE at `0x13aba60` describes `[0x5a8fd20, 0x5a8ff53)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a7ee20` | `e8fb0e0100` | `call 0x5a8fd20` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0ca8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a7e540 --stop-address=0x5a7ee25 "$target"
od -An -tx1 -j 105573552 -N 16 "$target"
objdump -s -j .rodata --start-address=0x440640 --stop-address=0x44065d "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35891ea300`), re-decoding lands at `0x64b0ca9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 191, column 17. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
