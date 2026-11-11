# RE-001: map node #115 node/hl_node.rs:289 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/hl_node.rs` as an embedded path. At ELF VA `0x2ce03bc` (file offset `0x2cdf3bc`), `4c8d0d65dd7603` decodes as `lea r9, [rip + 0x376dd65]`. Adding the signed displacement `58121573` to the next instruction VA `0x2ce03c3` yields `0x644e128`. The decode from the start of FDE range `[0x2cde430, 0x2ce0dd1)` reaches that instruction boundary. The FDE itself is at `0x11986ac`.

At `0x644e128` (file offset `0x644c128`), an `R_X86_64_RELATIVE` relocation points to `0x436a23` in `.rodata`. The next 16 bytes, `13000000000000002101000019000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 289 and 25. The string's normalized suffix matches `node/hl_node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `jne` and conditional jump at `0x2cdeb17` establish a local edge into the argument setup. The taken target is `0x2ce0399` and the fallthrough is `0x2cdeb1d`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2cdeb14` | `41390e` | `cmp dword ptr [r14], ecx` |
| `0x2cdeb17` | `0f857c180000` | `jne 0x2ce0399` |
| `0x2ce0399` | `488d442440` | `lea rax, [rsp + 0x40]` |
| `0x2ce039e` | `4889842490010000` | `mov qword ptr [rsp + 0x190], rax` |
| `0x2ce03a6` | `488b05bb0c8003` | `mov rax, qword ptr [rip + 0x3800cbb]` |
| `0x2ce03ad` | `4889842498010000` | `mov qword ptr [rsp + 0x198], rax` |
| `0x2ce03b5` | `488d0d1dd676fd` | `lea rcx, [rip - 0x28929e3]` |

## Argument flow

The LEA writes `r9`, the SysV x86-64 integer argument register 6. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -211330 added to `0x2ce03da` gives `0x2caca58`. The target's FDE at `0xd8afac` describes `[0x2caca58, 0x2caca8b)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ce03c3` | `488d742460` | `lea rsi, [rsp + 0x60]` |
| `0x2ce03c8` | `4c8d842490010000` | `lea r8, [rsp + 0x190]` |
| `0x2ce03d0` | `31ff` | `xor edi, edi` |
| `0x2ce03d2` | `4c89f2` | `mov rdx, r14` |
| `0x2ce03d5` | `e87ec6fcff` | `call 0x2caca58` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644e128 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2cde430 --stop-address=0x2ce03da "$target"
od -An -tx1 -j 105169200 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436a23 --stop-address=0x436a36 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d66dd7603`), re-decoding lands at `0x644e129`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 289, column 25. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
