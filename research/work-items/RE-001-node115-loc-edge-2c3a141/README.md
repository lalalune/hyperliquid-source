# RE-001: map node #115 l1/exchange/impl_abstraction.rs:279 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `l1/exchange/impl_abstraction.rs` as an embedded path. At ELF VA `0x2c3a141` (file offset `0x2c39141`), `4c8d0df8368103` decodes as `lea r9, [rip + 0x38136f8]`. Adding the signed displacement `58799864` to the next instruction VA `0x2c3a148` yields `0x644d840`. The decode from the start of FDE range `[0x2c3a010, 0x2c3a5e0)` reaches that instruction boundary. The FDE itself is at `0x118bb4c`.

At `0x644d840` (file offset `0x644b840`), an `R_X86_64_RELATIVE` relocation points to `0x438d15` in `.rodata`. The next 16 bytes, `2300000000000000170100001c000000`, decode as a little-endian 64-bit length of 35 and two 32-bit values, 279 and 28. The string's normalized suffix matches `l1/exchange/impl_abstraction.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `jne` and conditional jump at `0x2c3a13b` establish a local edge into the argument setup. The taken target is `0x2c3a434` and the fallthrough is `0x2c3a141`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `cmp r14d, 4`. The recorded edge reaches the load when the `jne` predicate (`ZF = 0`) is **false**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c3a137` | `4183fe04` | `cmp r14d, 4` |
| `0x2c3a13b` | `0f85f3020000` | `jne 0x2c3a434` |

## Argument flow

The LEA writes `r9`, the SysV x86-64 integer argument register 6. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -1777120 added to `0x2c3a160` gives `0x2a88380`. The target's FDE at `0xd7b26c` describes `[0x2a88380, 0x2a88641)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c3a148` | `4c89e7` | `mov rdi, r12` |
| `0x2c3a14b` | `4c89ee` | `mov rsi, r13` |
| `0x2c3a14e` | `488b542428` | `mov rdx, qword ptr [rsp + 0x28]` |
| `0x2c3a153` | `4889e9` | `mov rcx, rbp` |
| `0x2c3a156` | `4c8b442420` | `mov r8, qword ptr [rsp + 0x20]` |
| `0x2c3a15b` | `e820e2e4ff` | `call 0x2a88380` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d840 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c3a010 --stop-address=0x2c3a160 "$target"
od -An -tx1 -j 105166920 -N 16 "$target"
objdump -s -j .rodata --start-address=0x438d15 --stop-address=0x438d38 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0df9368103`), re-decoding lands at `0x644d841`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 279, column 28. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
