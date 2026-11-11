# RE-001: map node #115 base/u.rs:531 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x2701084` (file offset `0x2700084`), `488d151d65d303` decodes as `lea rdx, [rip + 0x3d3651d]`. Adding the signed displacement `64185629` to the next instruction VA `0x270108b` yields `0x64375a8`. The decode from the start of FDE range `[0x2701050, 0x27013d5)` reaches that instruction boundary. The FDE itself is at `0x1132c04`.

At `0x64375a8` (file offset `0x64355a8`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d000000000000001302000009000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 531 and 9. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2701078` establish a local edge into the argument setup. The taken target is `0x27010f6` and the fallthrough is `0x270107a`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2701076` | `85ed` | `test ebp, ebp` |
| `0x2701078` | `747c` | `je 0x27010f6` |
| `0x270107a` | `c644240700` | `mov byte ptr [rsp + 7], 0` |
| `0x270107f` | `c644244800` | `mov byte ptr [rsp + 0x48], 0` |

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -2814682 added to `0x270109a` gives `0x2451dc0`. The target's FDE at `0x110e114` describes `[0x2451dc0, 0x2451fbe)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x270108b` | `488d7c2407` | `lea rdi, [rsp + 7]` |
| `0x2701090` | `488d742448` | `lea rsi, [rsp + 0x48]` |
| `0x2701095` | `e8260dd5ff` | `call 0x2451dc0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64375a8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2701050 --stop-address=0x270109a "$target"
od -An -tx1 -j 105076144 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d151e65d303`), re-decoding lands at `0x64375a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 531, column 9. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
