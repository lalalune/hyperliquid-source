# RE-001: map node #115 node/consensus/execution_state.rs:128 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/consensus/execution_state.rs` as an embedded path. At ELF VA `0x2af720e` (file offset `0x2af620e`), `4c8d05330f9503` decodes as `lea r8, [rip + 0x3950f33]`. Adding the signed displacement `60100403` to the next instruction VA `0x2af7215` yields `0x6448148`. The decode from the start of FDE range `[0x2af7150, 0x2af77ee)` reaches that instruction boundary. The FDE itself is at `0x117caa8`.

At `0x6448148` (file offset `0x6446148`), an `R_X86_64_RELATIVE` relocation points to `0x44f5d5` in `.rodata`. The next 16 bytes, `25000000000000008000000022000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 128 and 34. The string's normalized suffix matches `node/consensus/execution_state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2af71d8` establish a local edge into the argument setup. The taken target is `0x2af7224` and the fallthrough is `0x2af71da`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2af71d6` | `84c0` | `test al, al` |
| `0x2af71d8` | `744a` | `je 0x2af7224` |
| `0x2af71da` | `498d742410` | `lea rsi, [r12 + 0x10]` |
| `0x2af71df` | `488d05d4eeb0fd` | `lea rax, [rip - 0x24f112c]` |
| `0x2af71e6` | `4889842488000000` | `mov qword ptr [rsp + 0x88], rax` |
| `0x2af71ee` | `48c784249000000019000000` | `mov qword ptr [rsp + 0x90], 0x19` |
| `0x2af71fa` | `48c784248000000000000000` | `mov qword ptr [rsp + 0x80], 0` |
| `0x2af7206` | `498dbc2440010000` | `lea rdi, [r12 + 0x140]` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -1300372 added to `0x2af7224` gives `0x29b9a90`. The target's FDE at `0x11617dc` describes `[0x29b9a90, 0x29ba3c7)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2af7215` | `488d942480000000` | `lea rdx, [rsp + 0x80]` |
| `0x2af721d` | `31c9` | `xor ecx, ecx` |
| `0x2af721f` | `e86c28ecff` | `call 0x29b9a90` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6448148 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2af7150 --stop-address=0x2af7224 "$target"
od -An -tx1 -j 105144656 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f5d5 --stop-address=0x44f5fa "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05340f9503`), re-decoding lands at `0x6448149`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 128, column 34. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
