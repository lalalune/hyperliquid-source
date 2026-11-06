# RE-001: map node #115 evm_rpc/evm_store.rs:627 conditional call edge

- Component allocation: `evm-rpc`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `evm_rpc/evm_store.rs` as an embedded path. At ELF VA `0x232e366` (file offset `0x232d366`), `4c8d05f3f80f04` decodes as `lea r8, [rip + 0x40ff8f3]`. Adding the signed displacement `68155635` to the next instruction VA `0x232e36d` yields `0x642dc60`. The decode from the start of FDE range `[0x232dff0, 0x232e7c5)` reaches that instruction boundary. The FDE itself is at `0x10f9554`.

At `0x642dc60` (file offset `0x642bc60`), an `R_X86_64_RELATIVE` relocation points to `0x44801d` in `.rodata`. The next 16 bytes, `18000000000000007302000020000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 627 and 32. The string's normalized suffix matches `evm_rpc/evm_store.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x232e2f7` establish a local edge into the argument setup. The taken target is `0x232e3bc` and the fallthrough is `0x232e2fd`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x232e2f1` | `4a837c323000` | `cmp qword ptr [rdx + r14 + 0x30], 0` |
| `0x232e2f7` | `0f84bf000000` | `je 0x232e3bc` |
| `0x232e2fd` | `488d0555cf2bfe` | `lea rax, [rip - 0x1d430ab]` |
| `0x232e304` | `48898424e8020000` | `mov qword ptr [rsp + 0x2e8], rax` |
| `0x232e30c` | `48c78424f002000013000000` | `mov qword ptr [rsp + 0x2f0], 0x13` |
| `0x232e318` | `48c78424e002000000000000` | `mov qword ptr [rsp + 0x2e0], 0` |
| `0x232e324` | `488b842480000000` | `mov rax, qword ptr [rsp + 0x80]` |
| `0x232e32c` | `48898424c0050000` | `mov qword ptr [rsp + 0x5c0], rax` |
| `0x232e334` | `488d8424c0000000` | `lea rax, [rsp + 0xc0]` |
| `0x232e33c` | `48898424c8050000` | `mov qword ptr [rsp + 0x5c8], rax` |
| `0x232e344` | `488d8424e0020000` | `lea rax, [rsp + 0x2e0]` |
| `0x232e34c` | `48898424d0050000` | `mov qword ptr [rsp + 0x5d0], rax` |
| `0x232e354` | `488d7c2420` | `lea rdi, [rsp + 0x20]` |
| `0x232e359` | `488bb42488000000` | `mov rsi, qword ptr [rsp + 0x88]` |
| `0x232e361` | `4c89e2` | `mov rdx, r12` |
| `0x232e364` | `31c9` | `xor ecx, ecx` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 6864990 added to `0x232e372` gives `0x29ba3d0`. The target's FDE at `0x1161848` describes `[0x29ba3d0, 0x29bad38)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x232e36d` | `e85ec06800` | `call 0x29ba3d0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642dc60 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x232dff0 --stop-address=0x232e372 "$target"
od -An -tx1 -j 105036904 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44801d --stop-address=0x448035 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05f4f80f04`), re-decoding lands at `0x642dc61`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 627, column 32. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
