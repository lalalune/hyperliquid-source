# RE-001: map node #115 l1/exchange/stake_requirement.rs:5 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/stake_requirement.rs` as an embedded path. At ELF VA `0x5b7a776` (file offset `0x5b79776`), `488d3d63669200` decodes as `lea rdi, [rip + 0x926663]`. Adding the signed displacement `9594467` to the next instruction VA `0x5b7a77d` yields `0x64a0de0`. The decode from the start of FDE range `[0x5b7a610, 0x5b7a82e)` reaches that instruction boundary. The FDE itself is at `0x13c07b0`.

At `0x64a0de0` (file offset `0x649ede0`), an `R_X86_64_RELATIVE` relocation points to `0x43f0ec` in `.rodata`. The next 16 bytes, `2400000000000000050000003e000000`, decode as a little-endian 64-bit length of 36 and two 32-bit values, 5 and 62. The string's normalized suffix matches `l1/exchange/stake_requirement.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5b7a770` is `0x5b7a6f0` and the fallthrough is `0x5b7a776`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test dl, al`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5b7a76e` | `84c2` | `test dl, al` |
| `0x5b7a770` | `0f847affffff` | `je 0x5b7a6f0` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 9851077 added to `0x5b7a783` gives the relocation slot `0x64df848`. Its symbol-zero RELATIVE addend is `0x1681e40`. The target's FDE at `0xcc3320` describes `[0x1681e40, 0x1681e59)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5b7a77d` | `ff15c5509600` | `call qword ptr [rip + 0x9650c5]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64a0de0 '
readelf -rW "$target" | grep -i '0*64df848 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5b7a610 --stop-address=0x5b7a783 "$target"
od -An -tx1 -j 105508328 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43f0ec --stop-address=0x43f110 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d64669200`), re-decoding lands at `0x64a0de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 5, column 62. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
