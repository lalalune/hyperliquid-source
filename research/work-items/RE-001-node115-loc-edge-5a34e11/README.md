# RE-001: map node #115 node/node.rs:652 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/node.rs` as an embedded path. At ELF VA `0x5a34e11` (file offset `0x5a33e11`), `4c8d0d083ca800` decodes as `lea r9, [rip + 0xa83c08]`. Adding the signed displacement `11025416` to the next instruction VA `0x5a34e18` yields `0x64b8a20`. The decode from the start of FDE range `[0x5a34440, 0x5a3539f)` reaches that instruction boundary. The FDE itself is at `0x13a1ea0`.

At `0x64b8a20` (file offset `0x64b6a20`), an `R_X86_64_RELATIVE` relocation points to `0x44aca3` in `.rodata`. The next 16 bytes, `10000000000000008c0200002a000000`, decode as a little-endian 64-bit length of 16 and two 32-bit values, 652 and 42. The string's normalized suffix matches `node/node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x5a34d24` establish a local edge into the argument setup. The taken target is `0x5a34db5` and the fallthrough is `0x5a34d2a`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `cmp dword ptr [rsp + 0xa88], 0`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **true**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a34d1c` | `83bc24880a000000` | `cmp dword ptr [rsp + 0xa88], 0` |
| `0x5a34d24` | `0f848b000000` | `je 0x5a34db5` |
| `0x5a34db5` | `8b442448` | `mov eax, dword ptr [rsp + 0x48]` |
| `0x5a34db9` | `488d8c24880a0000` | `lea rcx, [rsp + 0xa88]` |
| `0x5a34dc1` | `894108` | `mov dword ptr [rcx + 8], eax` |
| `0x5a34dc4` | `488b442440` | `mov rax, qword ptr [rsp + 0x40]` |
| `0x5a34dc9` | `488901` | `mov qword ptr [rcx], rax` |
| `0x5a34dcc` | `488b442410` | `mov rax, qword ptr [rsp + 0x10]` |
| `0x5a34dd1` | `488bb0a0000000` | `mov rsi, qword ptr [rax + 0xa0]` |
| `0x5a34dd8` | `488d5610` | `lea rdx, [rsi + 0x10]` |
| `0x5a34ddc` | `488d052962f0fa` | `lea rax, [rip - 0x50f9dd7]` |
| `0x5a34de3` | `4889442448` | `mov qword ptr [rsp + 0x48], rax` |
| `0x5a34de8` | `48c744245003000000` | `mov qword ptr [rsp + 0x50], 3` |
| `0x5a34df1` | `48c744244000000000` | `mov qword ptr [rsp + 0x40], 0` |
| `0x5a34dfa` | `4881c640010000` | `add rsi, 0x140` |
| `0x5a34e01` | `488dbc2490010000` | `lea rdi, [rsp + 0x190]` |
| `0x5a34e09` | `488d4c2440` | `lea rcx, [rsp + 0x40]` |
| `0x5a34e0e` | `4531c0` | `xor r8d, r8d` |

## Argument flow

The LEA writes `r9`, the SysV x86-64 integer argument register 6. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -11644541 added to `0x5a34e1d` gives `0x4f19fa0`. The target's FDE at `0x130afbc` describes `[0x4f19fa0, 0x4f1a938)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a34e18` | `e883514eff` | `call 0x4f19fa0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b8a20 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a34440 --stop-address=0x5a34e1d "$target"
od -An -tx1 -j 105605672 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44aca3 --stop-address=0x44acb3 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d093ca800`), re-decoding lands at `0x64b8a21`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 652, column 42. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
