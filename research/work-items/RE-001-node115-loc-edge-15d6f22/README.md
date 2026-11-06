# RE-001: map node #115 base/lu.rs:148 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `base/lu.rs` as an embedded path. At ELF VA `0x15d6f22` (file offset `0x15d5f22`), `488d15b7a5e204` decodes as `lea rdx, [rip + 0x4e2a5b7]`. Adding the signed displacement `81962423` to the next instruction VA `0x15d6f29` yields `0x64014e0`. The decode from the start of FDE range `[0x15d6ef0, 0x15d6fc4)` reaches that instruction boundary. The FDE itself is at `0x105b2cc`.

At `0x64014e0` (file offset `0x63ff4e0`), an `R_X86_64_RELATIVE` relocation points to `0x4326c1` in `.rodata`. The next 16 bytes, `0e000000000000009400000009000000`, decode as a little-endian 64-bit length of 14 and two 32-bit values, 148 and 9. The string's normalized suffix matches `base/lu.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x15d6f04` establish a local edge into the argument setup. The taken target is `0x15d6f22` and the fallthrough is `0x15d6f06`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15d6f01` | `4885ff` | `test rdi, rdi` |
| `0x15d6f04` | `741c` | `je 0x15d6f22` |

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -50516 added to `0x15d6f34` gives `0x15ca9e0`. The target's FDE at `0x105a5dc` describes `[0x15ca9e0, 0x15cac2a)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15d6f29` | `4c89f7` | `mov rdi, r14` |
| `0x15d6f2c` | `4889de` | `mov rsi, rbx` |
| `0x15d6f2f` | `e8ac3affff` | `call 0x15ca9e0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64014e0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x15d6ef0 --stop-address=0x15d6f34 "$target"
od -An -tx1 -j 104854760 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4326c1 --stop-address=0x4326cf "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15b8a5e204`), re-decoding lands at `0x64014e1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 148, column 9. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
