# RE-001: trace node #115 l1/staking.rs diagnostic argument to a direct call

- Component allocation: `staking`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `l1/staking.rs` as an embedded path. At ELF VA `0x3dd9890` (file offset `0x3dd8890`), `488d35490e6a02` decodes as `lea rsi, [rip + 0x26a0e49]`. Adding the signed displacement `40504905` to the next instruction VA `0x3dd9897` yields `0x647a6e0`. The decode from the start of FDE range `[0x3dd9480, 0x3dd99d3)` reaches that instruction boundary. The FDE itself is at `0x126f1ec`.

At `0x647a6e0` (file offset `0x64786e0`), an `R_X86_64_RELATIVE` relocation points to `0x44be29` in `.rodata`. The next 16 bytes, `11000000000000004501000040000000`, decode as a little-endian 64-bit length of 17 and two 32-bit values, 325 and 64. The string's normalized suffix matches `l1/staking.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rsi`, the SysV x86-64 integer argument register 2. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 5735748 added to `0x3dd989c` gives `0x4351de0`. The target's FDE at `0xe9e2a0` describes `[0x4351de0, 0x4351f56)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3dd9897` | `e844855700` | `call 0x4351de0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*647a6e0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x3dd9480 --stop-address=0x3dd989c "$target"
od -An -tx1 -j 105350888 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44be29 --stop-address=0x44be3a "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d354a0e6a02`), re-decoding lands at `0x647a6e1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 325, column 64. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
