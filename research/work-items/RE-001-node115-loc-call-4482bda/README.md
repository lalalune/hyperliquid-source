# RE-001: trace node #115 l1/clearinghouse/impl_first_dex.rs diagnostic argument to a direct call

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `l1/clearinghouse/impl_first_dex.rs` as an embedded path. At ELF VA `0x4482bda` (file offset `0x4481bda`), `488d3577910002` decodes as `lea rsi, [rip + 0x2009177]`. Adding the signed displacement `33591671` to the next instruction VA `0x4482be1` yields `0x648bd58`. The decode from the start of FDE range `[0x4482950, 0x44830f3)` reaches that instruction boundary. The FDE itself is at `0x12a55f8`.

At `0x648bd58` (file offset `0x6489d58`), an `R_X86_64_RELATIVE` relocation points to `0x437e0b` in `.rodata`. The next 16 bytes, `2600000000000000390000002f000000`, decode as a little-endian 64-bit length of 38 and two 32-bit values, 57 and 47. The string's normalized suffix matches `l1/clearinghouse/impl_first_dex.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rsi`, the SysV x86-64 integer argument register 2. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -1243867 added to `0x4482beb` gives `0x4353110`. The target's FDE at `0xe9e41c` describes `[0x4353110, 0x4353286)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4482be1` | `488d7c2420` | `lea rdi, [rsp + 0x20]` |
| `0x4482be6` | `e82505edff` | `call 0x4353110` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648bd58 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4482950 --stop-address=0x4482beb "$target"
od -An -tx1 -j 105422176 -N 16 "$target"
objdump -s -j .rodata --start-address=0x437e0b --stop-address=0x437e31 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3578910002`), re-decoding lands at `0x648bd59`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 57, column 47. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
