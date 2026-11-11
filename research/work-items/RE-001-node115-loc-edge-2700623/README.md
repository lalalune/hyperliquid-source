# RE-001: map node #115 base/u.rs:531 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x2700623` (file offset `0x26ff623`), `488d157e6fd303` decodes as `lea rdx, [rip + 0x3d36f7e]`. Adding the signed displacement `64188286` to the next instruction VA `0x270062a` yields `0x64375a8`. The decode from the start of FDE range `[0x27005e0, 0x2700cb6)` reaches that instruction boundary. The FDE itself is at `0x1132b5c`.

At `0x64375a8` (file offset `0x64355a8`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d000000000000001302000009000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 531 and 9. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2700613` establish a local edge into the argument setup. The taken target is `0x270069e` and the fallthrough is `0x2700619`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `test ebp, ebp`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **false**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2700611` | `85ed` | `test ebp, ebp` |
| `0x2700613` | `0f8485000000` | `je 0x270069e` |
| `0x2700619` | `c644240900` | `mov byte ptr [rsp + 9], 0` |
| `0x270061e` | `c644240a00` | `mov byte ptr [rsp + 0xa], 0` |

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -2813049 added to `0x2700639` gives `0x24519c0`. The target's FDE at `0x110e0ac` describes `[0x24519c0, 0x2451bbe)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x270062a` | `488d7c2409` | `lea rdi, [rsp + 9]` |
| `0x270062f` | `488d74240a` | `lea rsi, [rsp + 0xa]` |
| `0x2700634` | `e88713d5ff` | `call 0x24519c0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64375a8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x27005e0 --stop-address=0x2700639 "$target"
od -An -tx1 -j 105076144 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d157f6fd303`), re-decoding lands at `0x64375a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 531, column 9. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
