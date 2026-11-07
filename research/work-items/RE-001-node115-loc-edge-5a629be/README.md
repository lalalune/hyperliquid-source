# RE-001: map node #115 node/connections.rs:451 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/connections.rs` as an embedded path. At ELF VA `0x5a629be` (file offset `0x5a619be`), `4c8d050b5ca500` decodes as `lea r8, [rip + 0xa55c0b]`. Adding the signed displacement `10837003` to the next instruction VA `0x5a629c5` yields `0x64b85d0`. The decode from the start of FDE range `[0x5a628d0, 0x5a630f2)` reaches that instruction boundary. The FDE itself is at `0x13a9c40`.

At `0x64b85d0` (file offset `0x64b65d0`), an `R_X86_64_RELATIVE` relocation points to `0x445db6` in `.rodata`. The next 16 bytes, `1700000000000000c30100001e000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 451 and 30. The string's normalized suffix matches `node/connections.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x5a628ed` establish a local edge into the argument setup. The taken target is `0x5a62985` and the fallthrough is `0x5a628f3`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `cmp byte ptr [rcx], 0`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **true**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a628ea` | `803900` | `cmp byte ptr [rcx], 0` |
| `0x5a628ed` | `0f8492000000` | `je 0x5a62985` |
| `0x5a62985` | `4989ce` | `mov r14, rcx` |
| `0x5a62988` | `4c8b7920` | `mov r15, qword ptr [rcx + 0x20]` |
| `0x5a6298c` | `4d8d6710` | `lea r12, [r15 + 0x10]` |
| `0x5a62990` | `488d054482edfa` | `lea rax, [rip - 0x5127dbc]` |
| `0x5a62997` | `4889842488000000` | `mov qword ptr [rsp + 0x88], rax` |
| `0x5a6299f` | `48c784249000000025000000` | `mov qword ptr [rsp + 0x90], 0x25` |
| `0x5a629ab` | `48c784248000000000000000` | `mov qword ptr [rsp + 0x80], 0` |
| `0x5a629b7` | `4981c740010000` | `add r15, 0x140` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -11805194 added to `0x5a629da` gives `0x4f207d0`. The target's FDE at `0x130b418` describes `[0x4f207d0, 0x4f21105)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a629c5` | `488d942480000000` | `lea rdx, [rsp + 0x80]` |
| `0x5a629cd` | `4c89ff` | `mov rdi, r15` |
| `0x5a629d0` | `4c89e6` | `mov rsi, r12` |
| `0x5a629d3` | `31c9` | `xor ecx, ecx` |
| `0x5a629d5` | `e8f6dd4bff` | `call 0x4f207d0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b85d0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a628d0 --stop-address=0x5a629da "$target"
od -An -tx1 -j 105604568 -N 16 "$target"
objdump -s -j .rodata --start-address=0x445db6 --stop-address=0x445dcd "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d050c5ca500`), re-decoding lands at `0x64b85d1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 451, column 30. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
