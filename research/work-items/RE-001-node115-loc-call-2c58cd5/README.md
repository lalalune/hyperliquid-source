# RE-001: trace node #115 l1/exchange/stake_requirement.rs diagnostic argument to a direct call

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `l1/exchange/stake_requirement.rs` as an embedded path. At ELF VA `0x2c58cd5` (file offset `0x2c57cd5`), `488d35dc4b7f03` decodes as `lea rsi, [rip + 0x37f4bdc]`. Adding the signed displacement `58674140` to the next instruction VA `0x2c58cdc` yields `0x644d8b8`. The decode from the start of FDE range `[0x2c58c70, 0x2c59351)` reaches that instruction boundary. The FDE itself is at `0x118d0e8`.

At `0x644d8b8` (file offset `0x644b8b8`), an `R_X86_64_RELATIVE` relocation points to `0x43f0ec` in `.rodata`. The next 16 bytes, `2400000000000000400000001e000000`, decode as a little-endian 64-bit length of 36 and two 32-bit values, 64 and 30. The string's normalized suffix matches `l1/exchange/stake_requirement.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rsi`, the SysV x86-64 integer argument register 2. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -3321398 added to `0x2c58ce6` gives `0x292deb0`. The target's FDE at `0xd6e20c` describes `[0x292deb0, 0x292dfee)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c58cdc` | `488d7c2460` | `lea rdi, [rsp + 0x60]` |
| `0x2c58ce1` | `e8ca51cdff` | `call 0x292deb0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d8b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c58c70 --stop-address=0x2c58ce6 "$target"
od -An -tx1 -j 105167040 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43f0ec --stop-address=0x43f110 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35dd4b7f03`), re-decoding lands at `0x644d8b9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 64, column 30. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
