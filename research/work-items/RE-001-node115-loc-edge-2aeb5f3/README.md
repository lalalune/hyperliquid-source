# RE-001: map node #115 node/hl_node.rs:444 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/hl_node.rs` as an embedded path. At ELF VA `0x2aeb5f3` (file offset `0x2aea5f3`), `488d35f6c89503` decodes as `lea rsi, [rip + 0x395c8f6]`. Adding the signed displacement `60147958` to the next instruction VA `0x2aeb5fa` yields `0x6447ef0`. The decode from the start of FDE range `[0x2aeaef0, 0x2af0654)` reaches that instruction boundary. The FDE itself is at `0x117c598`.

At `0x6447ef0` (file offset `0x6445ef0`), an `R_X86_64_RELATIVE` relocation points to `0x436a23` in `.rodata`. The next 16 bytes, `1300000000000000bc01000011000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 444 and 17. The string's normalized suffix matches `node/hl_node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2aeb5dc` establish a local edge into the argument setup. The taken target is `0x2aebb0a` and the fallthrough is `0x2aeb5e2`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2aeb5d8` | `807b3802` | `cmp byte ptr [rbx + 0x38], 2` |
| `0x2aeb5dc` | `0f8428050000` | `je 0x2aebb0a` |
| `0x2aeb5e2` | `660f7f542430` | `movdqa xmmword ptr [rsp + 0x30], xmm2` |
| `0x2aeb5e8` | `660f7f4c2450` | `movdqa xmmword ptr [rsp + 0x50], xmm1` |
| `0x2aeb5ee` | `440fb67360` | `movzx r14d, byte ptr [rbx + 0x60]` |

## Argument flow

The LEA writes `rsi`, the SysV x86-64 integer argument register 2. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 1652873 added to `0x2aeb607` gives `0x2c7ee90`. The target's FDE at `0x118e3c8` describes `[0x2c7ee90, 0x2c7f0f5)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2aeb5fa` | `488dbc24e0030000` | `lea rdi, [rsp + 0x3e0]` |
| `0x2aeb602` | `e889381900` | `call 0x2c7ee90` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6447ef0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2aeaef0 --stop-address=0x2aeb607 "$target"
od -An -tx1 -j 105144056 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436a23 --stop-address=0x436a36 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35f7c89503`), re-decoding lands at `0x6447ef1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 444, column 17. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
