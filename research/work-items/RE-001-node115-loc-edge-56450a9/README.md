# RE-001: map node #115 node/gossip_config.rs:60 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/gossip_config.rs` as an embedded path. At ELF VA `0x56450a9` (file offset `0x56440a9`), `488d15605ee600` decodes as `lea rdx, [rip + 0xe65e60]`. Adding the signed displacement `15097440` to the next instruction VA `0x56450b0` yields `0x64aaf10`. The decode from the start of FDE range `[0x5644fd0, 0x5645ffb)` reaches that instruction boundary. The FDE itself is at `0x1367000`.

At `0x64aaf10` (file offset `0x64a8f10`), an `R_X86_64_RELATIVE` relocation points to `0x449029` in `.rodata`. The next 16 bytes, `19000000000000003c00000032000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 60 and 50. The string's normalized suffix matches `node/gossip_config.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x5645066` establish a local edge into the argument setup. The taken target is `0x5645da6` and the fallthrough is `0x564506c`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5645063` | `4885c0` | `test rax, rax` |
| `0x5645066` | `0f843a0d0000` | `je 0x5645da6` |
| `0x564506c` | `0f1005f3572efb` | `movups xmm0, xmmword ptr [rip - 0x4d1a80d]` |
| `0x5645073` | `0f11400b` | `movups xmmword ptr [rax + 0xb], xmm0` |
| `0x5645077` | `0f1005dd572efb` | `movups xmm0, xmmword ptr [rip - 0x4d1a823]` |
| `0x564507e` | `0f1100` | `movups xmmword ptr [rax], xmm0` |
| `0x5645081` | `48c78424900000001b000000` | `mov qword ptr [rsp + 0x90], 0x1b` |
| `0x564508d` | `4889842498000000` | `mov qword ptr [rsp + 0x98], rax` |
| `0x5645095` | `48c78424a00000001b000000` | `mov qword ptr [rsp + 0xa0], 0x1b` |
| `0x56450a1` | `c68424a800000001` | `mov byte ptr [rsp + 0xa8], 1` |

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 1627416 added to `0x56450c8` gives `0x57d25e0`. The target's FDE at `0x1376fac` describes `[0x57d25e0, 0x57d27c8)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x56450b0` | `488dbc24e0010000` | `lea rdi, [rsp + 0x1e0]` |
| `0x56450b8` | `4c8da42490000000` | `lea r12, [rsp + 0x90]` |
| `0x56450c0` | `4c89e6` | `mov rsi, r12` |
| `0x56450c3` | `e818d51800` | `call 0x57d25e0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aaf10 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5644fd0 --stop-address=0x56450c8 "$target"
od -An -tx1 -j 105549592 -N 16 "$target"
objdump -s -j .rodata --start-address=0x449029 --stop-address=0x449042 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15615ee600`), re-decoding lands at `0x64aaf11`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 60, column 50. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
