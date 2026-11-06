# RE-001: trace node #115 info_server/abci_state_info_handler.rs diagnostic argument to a direct call

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x297868f` (file offset `0x297768f`), `488d0d4aa7ac03` decodes as `lea rcx, [rip + 0x3aca74a]`. Adding the signed displacement `61646666` to the next instruction VA `0x2978696` yields `0x6442de0`. The decode from the start of FDE range `[0x2978640, 0x29786d0)` reaches that instruction boundary. The FDE itself is at `0x115dc24`.

At `0x6442de0` (file offset `0x6440de0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000005200000010000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 82 and 16. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 323166 added to `0x29786a2` gives `0x29c7500`. The target's FDE at `0x1161fc8` describes `[0x29c7500, 0x29c7e37)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2978696` | `488d742418` | `lea rsi, [rsp + 0x18]` |
| `0x297869b` | `31d2` | `xor edx, edx` |
| `0x297869d` | `e85eee0400` | `call 0x29c7500` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6442de0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2978640 --stop-address=0x29786a2 "$target"
od -An -tx1 -j 105123304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d4ba7ac03`), re-decoding lands at `0x6442de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 82, column 16. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
