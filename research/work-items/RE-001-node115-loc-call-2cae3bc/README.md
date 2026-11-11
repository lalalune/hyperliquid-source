# RE-001: trace node #115 node/gossip_config.rs diagnostic argument to a direct call

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `node/gossip_config.rs` as an embedded path. At ELF VA `0x2cae3bc` (file offset `0x2cad3bc`), `4c8d0d7dfa7903` decodes as `lea r9, [rip + 0x379fa7d]`. Adding the signed displacement `58325629` to the next instruction VA `0x2cae3c3` yields `0x644de40`. The decode from the start of FDE range `[0x2cad9b0, 0x2cb1dff)` reaches that instruction boundary. The FDE itself is at `0x1196788`.

At `0x644de40` (file offset `0x644be40`), an `R_X86_64_RELATIVE` relocation points to `0x449029` in `.rodata`. The next 16 bytes, `1900000000000000830100001b000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 387 and 27. The string's normalized suffix matches `node/gossip_config.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `r9`, the SysV x86-64 integer argument register 6. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -3003915 added to `0x2cae3db` gives `0x29d0dd0`. The target's FDE at `0x1162568` describes `[0x29d0dd0, 0x29d179d)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2cae3c3` | `488dbc2470010000` | `lea rdi, [rsp + 0x170]` |
| `0x2cae3cb` | `488d8c2440030000` | `lea rcx, [rsp + 0x340]` |
| `0x2cae3d3` | `4531c0` | `xor r8d, r8d` |
| `0x2cae3d6` | `e8f529d2ff` | `call 0x29d0dd0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644de40 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2cad9b0 --stop-address=0x2cae3db "$target"
od -An -tx1 -j 105168456 -N 16 "$target"
objdump -s -j .rodata --start-address=0x449029 --stop-address=0x449042 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d7efa7903`), re-decoding lands at `0x644de41`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 387, column 27. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
