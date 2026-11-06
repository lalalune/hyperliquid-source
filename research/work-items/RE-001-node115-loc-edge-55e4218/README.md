# RE-001: map node #115 l1/exchange/simulate_portfolio_margin.rs:130 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `l1/exchange/simulate_portfolio_margin.rs` as an embedded path. At ELF VA `0x55e4218` (file offset `0x55e3218`), `488d0d0164ec00` decodes as `lea rcx, [rip + 0xec6401]`. Adding the signed displacement `15492097` to the next instruction VA `0x55e421f` yields `0x64aa620`. The decode from the start of FDE range `[0x55e3770, 0x55e4ad0)` reaches that instruction boundary. The FDE itself is at `0x135e3a8`.

At `0x64aa620` (file offset `0x64a8620`), an `R_X86_64_RELATIVE` relocation points to `0x43e0eb` in `.rodata`. The next 16 bytes, `2c000000000000008200000030000000`, decode as a little-endian 64-bit length of 44 and two 32-bit values, 130 and 48. The string's normalized suffix matches `l1/exchange/simulate_portfolio_margin.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x55e43a4` establish a local edge into the argument setup. The taken target is `0x55e4210` and the fallthrough is `0x55e43aa`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55e439c` | `83bc245001000003` | `cmp dword ptr [rsp + 0x150], 3` |
| `0x55e43a4` | `0f8466feffff` | `je 0x55e4210` |
| `0x55e4210` | `488dbc2448020000` | `lea rdi, [rsp + 0x248]` |

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -8542794 added to `0x55e422a` gives `0x4dbe7e0`. The target's FDE at `0xf226a0` describes `[0x4dbe7e0, 0x4dbe901)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55e421f` | `4c89ee` | `mov rsi, r13` |
| `0x55e4222` | `4889ea` | `mov rdx, rbp` |
| `0x55e4225` | `e8b6a57dff` | `call 0x4dbe7e0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa620 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x55e3770 --stop-address=0x55e43aa "$target"
od -An -tx1 -j 105547304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43e0eb --stop-address=0x43e117 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d0264ec00`), re-decoding lands at `0x64aa621`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 130, column 48. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
