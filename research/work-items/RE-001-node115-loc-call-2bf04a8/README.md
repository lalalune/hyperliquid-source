# RE-001: trace node #115 l1/exchange/impl_global.rs diagnostic argument to a direct call

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `l1/exchange/impl_global.rs` as an embedded path. At ELF VA `0x2bf04a8` (file offset `0x2bef4a8`), `488d0d89f58303` decodes as `lea rcx, [rip + 0x383f589]`. Adding the signed displacement `58979721` to the next instruction VA `0x2bf04af` yields `0x642fa38`. The decode from the start of FDE range `[0x2bf00f0, 0x2bf1e87)` reaches that instruction boundary. The FDE itself is at `0x1188898`.

At `0x642fa38` (file offset `0x642da38`), an `R_X86_64_RELATIVE` relocation points to `0x4308e8` in `.rodata`. The next 16 bytes, `1e00000000000000ce0300002e000000`, decode as a little-endian 64-bit length of 30 and two 32-bit values, 974 and 46. The string's normalized suffix matches `l1/exchange/impl_global.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -3425746 added to `0x2bf04c2` gives `0x28abef0`. The target's FDE at `0x1154a98` describes `[0x28abef0, 0x28ac489)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2bf04af` | `488dbc24f0010000` | `lea rdi, [rsp + 0x1f0]` |
| `0x2bf04b7` | `4889ee` | `mov rsi, rbp` |
| `0x2bf04ba` | `4c89fa` | `mov rdx, r15` |
| `0x2bf04bd` | `e82ebacbff` | `call 0x28abef0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642fa38 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2bf00f0 --stop-address=0x2bf04c2 "$target"
od -An -tx1 -j 105044544 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4308e8 --stop-address=0x430906 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d8af58303`), re-decoding lands at `0x642fa39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 974, column 46. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
