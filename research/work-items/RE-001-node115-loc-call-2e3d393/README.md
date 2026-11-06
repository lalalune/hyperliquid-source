# RE-001: trace node #115 evm_rpc/method_router.rs diagnostic argument to a direct call

- Component allocation: `evm-rpc`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `evm_rpc/method_router.rs` as an embedded path. At ELF VA `0x2e3d393` (file offset `0x2e3c393`), `488d0d865a6103` decodes as `lea rcx, [rip + 0x3615a86]`. Adding the signed displacement `56711814` to the next instruction VA `0x2e3d39a` yields `0x6452e20`. The decode from the start of FDE range `[0x2e3cb60, 0x2e3ed03)` reaches that instruction boundary. The FDE itself is at `0x11b3108`.

At `0x6452e20` (file offset `0x6450e20`), an `R_X86_64_RELATIVE` relocation points to `0x444dae` in `.rodata`. The next 16 bytes, `1c000000000000006000000024000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 96 and 36. The string's normalized suffix matches `evm_rpc/method_router.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -4701689 added to `0x2e3d3a9` gives `0x29c15b0`. The target's FDE at `0x1161c68` describes `[0x29c15b0, 0x29c1ed5)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2e3d39a` | `488db424e0000000` | `lea rsi, [rsp + 0xe0]` |
| `0x2e3d3a2` | `31d2` | `xor edx, edx` |
| `0x2e3d3a4` | `e80742b8ff` | `call 0x29c15b0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6452e20 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2e3cb60 --stop-address=0x2e3d3a9 "$target"
od -An -tx1 -j 105188904 -N 16 "$target"
objdump -s -j .rodata --start-address=0x444dae --stop-address=0x444dca "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d875a6103`), re-decoding lands at `0x6452e21`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 96, column 36. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
