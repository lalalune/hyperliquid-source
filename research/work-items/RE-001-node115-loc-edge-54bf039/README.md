# RE-001: map node #115 l1/exchange/impl_bole.rs:547 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `l1/exchange/impl_bole.rs` as an embedded path. At ELF VA `0x54bf039` (file offset `0x54be039`), `488d0d28b6fe00` decodes as `lea rcx, [rip + 0xfeb628]`. Adding the signed displacement `16692776` to the next instruction VA `0x54bf040` yields `0x64aa668`. The decode from the start of FDE range `[0x54b66b0, 0x54c2ae8)` reaches that instruction boundary. The FDE itself is at `0x1353a04`.

At `0x64aa668` (file offset `0x64a8668`), an `R_X86_64_RELATIVE` relocation points to `0x43df9f` in `.rodata`. The next 16 bytes, `1c00000000000000230200002b000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 547 and 43. The string's normalized suffix matches `l1/exchange/impl_bole.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x54bf019` establish a local edge into the argument setup. The taken target is `0x54bf139` and the fallthrough is `0x54bf01f`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `test rax, rax`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **false**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54bf016` | `4885c0` | `test rax, rax` |
| `0x54bf019` | `0f841a010000` | `je 0x54bf139` |
| `0x54bf01f` | `4829f8` | `sub rax, rdi` |
| `0x54bf022` | `bb00000000` | `mov ebx, 0` |
| `0x54bf027` | `480f43d8` | `cmovae rbx, rax` |
| `0x54bf02b` | `488dbc24e0010000` | `lea rdi, [rsp + 0x1e0]` |
| `0x54bf033` | `4c89f6` | `mov rsi, r14` |
| `0x54bf036` | `4889da` | `mov rdx, rbx` |

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -7340661 added to `0x54bf045` gives `0x4dbedd0`. The target's FDE at `0x12f80d8` describes `[0x4dbedd0, 0x4dbf226)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54bf040` | `e88bfd8fff` | `call 0x4dbedd0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa668 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x54b66b0 --stop-address=0x54bf045 "$target"
od -An -tx1 -j 105547376 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43df9f --stop-address=0x43dfbb "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d29b6fe00`), re-decoding lands at `0x64aa669`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 547, column 43. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
