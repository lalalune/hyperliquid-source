# RE-001: map node #115 l1/exchange/impl_bole.rs:547 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `l1/exchange/impl_bole.rs` as an embedded path. At ELF VA `0x2a8c183` (file offset `0x2a8b183`), `488d0d86ad9b03` decodes as `lea rcx, [rip + 0x39bad86]`. Adding the signed displacement `60534150` to the next instruction VA `0x2a8c18a` yields `0x6446f10`. The decode from the start of FDE range `[0x2a8be00, 0x2a8cbb3)` reaches that instruction boundary. The FDE itself is at `0x116f978`.

At `0x6446f10` (file offset `0x6444f10`), an `R_X86_64_RELATIVE` relocation points to `0x43df9f` in `.rodata`. The next 16 bytes, `1c00000000000000230200002b000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 547 and 43. The string's normalized suffix matches `l1/exchange/impl_bole.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2a8c166` establish a local edge into the argument setup. The taken target is `0x2a8c28c` and the fallthrough is `0x2a8c16c`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a8c163` | `4885c0` | `test rax, rax` |
| `0x2a8c166` | `0f8420010000` | `je 0x2a8c28c` |
| `0x2a8c16c` | `4829f8` | `sub rax, rdi` |
| `0x2a8c16f` | `bb00000000` | `mov ebx, 0` |
| `0x2a8c174` | `480f43d8` | `cmovae rbx, rax` |
| `0x2a8c178` | `488d7c2470` | `lea rdi, [rsp + 0x70]` |
| `0x2a8c17d` | `4889ee` | `mov rsi, rbp` |
| `0x2a8c180` | `4889da` | `mov rdx, rbx` |

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 3289425 added to `0x2a8c18f` gives `0x2daf2e0`. The target's FDE at `0x11a3940` describes `[0x2daf2e0, 0x2daf736)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a8c18a` | `e851313200` | `call 0x2daf2e0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6446f10 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2a8be00 --stop-address=0x2a8c18f "$target"
od -An -tx1 -j 105139992 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43df9f --stop-address=0x43dfbb "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d87ad9b03`), re-decoding lands at `0x6446f11`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 547, column 43. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
