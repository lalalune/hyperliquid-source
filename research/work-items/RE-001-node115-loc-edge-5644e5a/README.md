# RE-001: map node #115 node/gossip_config.rs:113 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/gossip_config.rs` as an embedded path. At ELF VA `0x5644e5a` (file offset `0x5643e5a`), `488d0d9760e600` decodes as `lea rcx, [rip + 0xe66097]`. Adding the signed displacement `15098007` to the next instruction VA `0x5644e61` yields `0x64aaef8`. The decode from the start of FDE range `[0x5644c40, 0x5644fc7)` reaches that instruction boundary. The FDE itself is at `0x1366fc0`.

At `0x64aaef8` (file offset `0x64a8ef8`), an `R_X86_64_RELATIVE` relocation points to `0x449029` in `.rodata`. The next 16 bytes, `1900000000000000710000005d000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 113 and 93. The string's normalized suffix matches `node/gossip_config.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x5644e23` establish a local edge into the argument setup. The taken target is `0x5644f48` and the fallthrough is `0x5644e29`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5644e20` | `4885c0` | `test rax, rax` |
| `0x5644e23` | `0f841f010000` | `je 0x5644f48` |
| `0x5644e29` | `0f1005365a2efb` | `movups xmm0, xmmword ptr [rip - 0x4d1a5ca]` |
| `0x5644e30` | `0f11400b` | `movups xmmword ptr [rax + 0xb], xmm0` |
| `0x5644e34` | `0f1005205a2efb` | `movups xmm0, xmmword ptr [rip - 0x4d1a5e0]` |
| `0x5644e3b` | `0f1100` | `movups xmmword ptr [rax], xmm0` |
| `0x5644e3e` | `48c74424101b000000` | `mov qword ptr [rsp + 0x10], 0x1b` |
| `0x5644e47` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x5644e4c` | `48c74424201b000000` | `mov qword ptr [rsp + 0x20], 0x1b` |
| `0x5644e55` | `c644242800` | `mov byte ptr [rsp + 0x28], 0` |

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 1627016 added to `0x5644e78` gives `0x57d2200`. The target's FDE at `0x1376f58` describes `[0x57d2200, 0x57d25d4)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5644e61` | `488dbc2498010000` | `lea rdi, [rsp + 0x198]` |
| `0x5644e69` | `488d742410` | `lea rsi, [rsp + 0x10]` |
| `0x5644e6e` | `488d54240f` | `lea rdx, [rsp + 0xf]` |
| `0x5644e73` | `e888d31800` | `call 0x57d2200` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aaef8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5644c40 --stop-address=0x5644e78 "$target"
od -An -tx1 -j 105549568 -N 16 "$target"
objdump -s -j .rodata --start-address=0x449029 --stop-address=0x449042 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d9860e600`), re-decoding lands at `0x64aaef9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 113, column 93. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
