# RE-001: map node #115 info_server/abci_state_info_handler.rs:82 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x29797b3` (file offset `0x29787b3`), `4c8d052696ac03` decodes as `lea r8, [rip + 0x3ac9626]`. Adding the signed displacement `61642278` to the next instruction VA `0x29797ba` yields `0x6442de0`. The decode from the start of FDE range `[0x2979780, 0x29797f9)` reaches that instruction boundary. The FDE itself is at `0x115e034`.

At `0x6442de0` (file offset `0x6440de0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000005200000010000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 82 and 16. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `jne` and conditional jump at `0x297978b` establish a local edge into the argument setup. The taken target is `0x29797d5` and the fallthrough is `0x297978d`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `test eax, eax`. The recorded edge reaches the load when the `jne` predicate (`ZF = 0`) is **false**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2979789` | `85c0` | `test eax, eax` |
| `0x297978b` | `7548` | `jne 0x29797d5` |
| `0x297978d` | `4889fb` | `mov rbx, rdi` |
| `0x2979790` | `488b07` | `mov rax, qword ptr [rdi]` |
| `0x2979793` | `488b38` | `mov rdi, qword ptr [rax]` |
| `0x2979796` | `488d7710` | `lea rsi, [rdi + 0x10]` |
| `0x297979a` | `0f104308` | `movups xmm0, xmmword ptr [rbx + 8]` |
| `0x297979e` | `0f11442410` | `movups xmmword ptr [rsp + 0x10], xmm0` |
| `0x29797a3` | `48c744240800000000` | `mov qword ptr [rsp + 8], 0` |
| `0x29797ac` | `4881c740010000` | `add rdi, 0x140` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 384938 added to `0x29797c6` gives `0x29d7770`. The target's FDE at `0x116294c` describes `[0x29d7770, 0x29d80e2)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x29797ba` | `488d542408` | `lea rdx, [rsp + 8]` |
| `0x29797bf` | `31c9` | `xor ecx, ecx` |
| `0x29797c1` | `e8aadf0500` | `call 0x29d7770` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6442de0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2979780 --stop-address=0x29797c6 "$target"
od -An -tx1 -j 105123304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d052796ac03`), re-decoding lands at `0x6442de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 82, column 16. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
