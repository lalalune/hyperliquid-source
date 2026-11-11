# RE-001: map node #115 node/consensus/server.rs:613 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/consensus/server.rs` as an embedded path. At ELF VA `0x2af9d65` (file offset `0x2af8d65`), `488d15e4e49403` decodes as `lea rdx, [rip + 0x394e4e4]`. Adding the signed displacement `60089572` to the next instruction VA `0x2af9d6c` yields `0x6448250`. The decode from the start of FDE range `[0x2af9c10, 0x2afa13f)` reaches that instruction boundary. The FDE itself is at `0x117cba4`.

At `0x6448250` (file offset `0x6446250`), an `R_X86_64_RELATIVE` relocation points to `0x432bae` in `.rodata`. The next 16 bytes, `1c000000000000006502000032000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 613 and 50. The string's normalized suffix matches `node/consensus/server.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2af9d38` establish a local edge into the argument setup. The taken target is `0x2af9d4f` and the fallthrough is `0x2af9d3a`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2af9d36` | `84c0` | `test al, al` |
| `0x2af9d38` | `7415` | `je 0x2af9d4f` |
| `0x2af9d4f` | `4c89742440` | `mov qword ptr [rsp + 0x40], r14` |
| `0x2af9d54` | `4c89642448` | `mov qword ptr [rsp + 0x48], r12` |
| `0x2af9d59` | `4c896c2450` | `mov qword ptr [rsp + 0x50], r13` |
| `0x2af9d5e` | `488dbbe8000000` | `lea rdi, [rbx + 0xe8]` |

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 2048138 added to `0x2af9d76` gives `0x2cede00`. The target's FDE at `0x1198da0` describes `[0x2cede00, 0x2cedf53)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2af9d6c` | `488d742440` | `lea rsi, [rsp + 0x40]` |
| `0x2af9d71` | `e88a401f00` | `call 0x2cede00` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6448250 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2af9c10 --stop-address=0x2af9d76 "$target"
od -An -tx1 -j 105144920 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432bae --stop-address=0x432bca "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15e5e49403`), re-decoding lands at `0x6448251`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 613, column 50. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
