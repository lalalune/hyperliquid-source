# RE-001: map node #115 node/nv_stream.rs:199 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/nv_stream.rs` as an embedded path. At ELF VA `0x5a8619f` (file offset `0x5a8519f`), `488d155230a300` decodes as `lea rdx, [rip + 0xa33052]`. Adding the signed displacement `10694738` to the next instruction VA `0x5a861a6` yields `0x64b91f8`. The decode from the start of FDE range `[0x5a82670, 0x5a89535)` reaches that instruction boundary. The FDE itself is at `0x13aa93c`.

At `0x64b91f8` (file offset `0x64b71f8`), an `R_X86_64_RELATIVE` relocation points to `0x43bce4` in `.rodata`. The next 16 bytes, `1500000000000000c70000002c000000`, decode as a little-endian 64-bit length of 21 and two 32-bit values, 199 and 44. The string's normalized suffix matches `node/nv_stream.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x5a86105` establish a local edge into the argument setup. The taken target is `0x5a8614d` and the fallthrough is `0x5a86107`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `test r14, r14`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **true**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a86102` | `4d85f6` | `test r14, r14` |
| `0x5a86105` | `7446` | `je 0x5a8614d` |
| `0x5a8614d` | `48c7832801000000000000` | `mov qword ptr [rbx + 0x128], 0` |
| `0x5a86158` | `48c7833001000001000000` | `mov qword ptr [rbx + 0x130], 1` |
| `0x5a86163` | `660fefc0` | `pxor xmm0, xmm0` |
| `0x5a86167` | `f30f7f8338010000` | `movdqu xmmword ptr [rbx + 0x138], xmm0` |
| `0x5a8616f` | `48c7834801000000000000` | `mov qword ptr [rbx + 0x148], 0` |
| `0x5a8617a` | `48c7835001000008000000` | `mov qword ptr [rbx + 0x150], 8` |
| `0x5a86185` | `c6837001000000` | `mov byte ptr [rbx + 0x170], 0` |
| `0x5a8618c` | `f30f7f8358010000` | `movdqu xmmword ptr [rbx + 0x158], xmm0` |
| `0x5a86194` | `48c78368010000a0860100` | `mov qword ptr [rbx + 0x168], 0x186a0` |

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -1186856 added to `0x5a861b8` gives `0x5964590`. The target's FDE at `0x13914e4` describes `[0x5964590, 0x5964709)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a861a6` | `488dbc2420140000` | `lea rdi, [rsp + 0x1420]` |
| `0x5a861ae` | `bee8030000` | `mov esi, 0x3e8` |
| `0x5a861b3` | `e8d8e3edff` | `call 0x5964590` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b91f8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a82670 --stop-address=0x5a861b8 "$target"
od -An -tx1 -j 105607680 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43bce4 --stop-address=0x43bcf9 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d155330a300`), re-decoding lands at `0x64b91f9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 199, column 44. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
