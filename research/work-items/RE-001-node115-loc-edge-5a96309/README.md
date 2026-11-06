# RE-001: map node #115 base/fu.rs:195 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `base/fu.rs` as an embedded path. At ELF VA `0x5a96309` (file offset `0x5a95309`), `488d0d081ea200` decodes as `lea rcx, [rip + 0xa21e08]`. Adding the signed displacement `10624520` to the next instruction VA `0x5a96310` yields `0x64b8118`. The decode from the start of FDE range `[0x5a96140, 0x5a9679a)` reaches that instruction boundary. The FDE itself is at `0x13ac7c0`.

At `0x64b8118` (file offset `0x64b6118`), an `R_X86_64_RELATIVE` relocation points to `0x43caab` in `.rodata`. The next 16 bytes, `0e00000000000000c300000020000000`, decode as a little-endian 64-bit length of 14 and two 32-bit values, 195 and 32. The string's normalized suffix matches `base/fu.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x5a962e5` establish a local edge into the argument setup. The taken target is `0x5a96303` and the fallthrough is `0x5a962e7`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a962e2` | `83f801` | `cmp eax, 1` |
| `0x5a962e5` | `741c` | `je 0x5a96303` |
| `0x5a96303` | `6441c6474400` | `mov byte ptr fs:[r15 + 0x44], 0` |

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -10197984 added to `0x5a96320` gives `0x50dc740`. The target's FDE at `0x131ad18` describes `[0x50dc740, 0x50dca9b)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a96310` | `488d7c2408` | `lea rdi, [rsp + 8]` |
| `0x5a96315` | `4889ee` | `mov rsi, rbp` |
| `0x5a96318` | `4c89f2` | `mov rdx, r14` |
| `0x5a9631b` | `e8206464ff` | `call 0x50dc740` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b8118 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a96140 --stop-address=0x5a96320 "$target"
od -An -tx1 -j 105603360 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43caab --stop-address=0x43cab9 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d091ea200`), re-decoding lands at `0x64b8119`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 195, column 32. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
