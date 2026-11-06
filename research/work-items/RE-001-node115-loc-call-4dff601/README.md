# RE-001: trace node #115 node/consensus/execution_state.rs diagnostic argument to a direct call

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `node/consensus/execution_state.rs` as an embedded path. At ELF VA `0x4dff601` (file offset `0x4dfe601`), `488d1520d76901` decodes as `lea rdx, [rip + 0x169d720]`. Adding the signed displacement `23713568` to the next instruction VA `0x4dff608` yields `0x649cd28`. The decode from the start of FDE range `[0x4dfe6d0, 0x4dff979)` reaches that instruction boundary. The FDE itself is at `0x130072c`.

At `0x649cd28` (file offset `0x649ad28`), an `R_X86_64_RELATIVE` relocation points to `0x44f5d5` in `.rodata`. The next 16 bytes, `2500000000000000990000001e000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 153 and 30. The string's normalized suffix matches `node/consensus/execution_state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 13313515 added to `0x4dff615` gives `0x5ab1c00`. The target's FDE at `0x13ae288` describes `[0x5ab1c00, 0x5ab1cdd)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4dff608` | `488db42420030000` | `lea rsi, [rsp + 0x320]` |
| `0x4dff610` | `e8eb25cb00` | `call 0x5ab1c00` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649cd28 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4dfe6d0 --stop-address=0x4dff615 "$target"
od -An -tx1 -j 105491760 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f5d5 --stop-address=0x44f5fa "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1521d76901`), re-decoding lands at `0x649cd29`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 153, column 30. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
