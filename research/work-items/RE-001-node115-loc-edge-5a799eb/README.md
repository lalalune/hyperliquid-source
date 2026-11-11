# RE-001: map node #115 node/consensus/rpc.rs:218 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/consensus/rpc.rs` as an embedded path. At ELF VA `0x5a799eb` (file offset `0x5a789eb`), `4c8d0d46f3a300` decodes as `lea r9, [rip + 0xa3f346]`. Adding the signed displacement `10744646` to the next instruction VA `0x5a799f2` yields `0x64b8d38`. The decode from the start of FDE range `[0x5a79730, 0x5a7b155)` reaches that instruction boundary. The FDE itself is at `0x13aa4b0`.

At `0x64b8d38` (file offset `0x64b6d38`), an `R_X86_64_RELATIVE` relocation points to `0x432e8e` in `.rodata`. The next 16 bytes, `1900000000000000da0000001f000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 218 and 31. The string's normalized suffix matches `node/consensus/rpc.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x5a79958` establish a local edge into the argument setup. The taken target is `0x5a799ae` and the fallthrough is `0x5a7995a`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a79956` | `84c0` | `test al, al` |
| `0x5a79958` | `7454` | `je 0x5a799ae` |
| `0x5a799ae` | `488b83b8000000` | `mov rax, qword ptr [rbx + 0xb8]` |
| `0x5a799b5` | `488b7010` | `mov rsi, qword ptr [rax + 0x10]` |
| `0x5a799b9` | `488d5610` | `lea rdx, [rsi + 0x10]` |
| `0x5a799bd` | `488d057018ecfa` | `lea rax, [rip - 0x513e790]` |
| `0x5a799c4` | `4889842488000000` | `mov qword ptr [rsp + 0x88], rax` |
| `0x5a799cc` | `48c784249000000019000000` | `mov qword ptr [rsp + 0x90], 0x19` |
| `0x5a799d8` | `48c784248000000000000000` | `mov qword ptr [rsp + 0x80], 0` |
| `0x5a799e4` | `4881c640010000` | `add rsi, 0x140` |

## Argument flow

The LEA writes `r9`, the SysV x86-64 integer argument register 6. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -11918858 added to `0x5a79a0a` gives `0x4f1bc00`. The target's FDE at `0x130b0e8` describes `[0x4f1bc00, 0x4f1c598)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a799f2` | `488dbc24c8020000` | `lea rdi, [rsp + 0x2c8]` |
| `0x5a799fa` | `488d8c2480000000` | `lea rcx, [rsp + 0x80]` |
| `0x5a79a02` | `4531c0` | `xor r8d, r8d` |
| `0x5a79a05` | `e8f6214aff` | `call 0x4f1bc00` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b8d38 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a79730 --stop-address=0x5a79a0a "$target"
od -An -tx1 -j 105606464 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432e8e --stop-address=0x432ea7 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d47f3a300`), re-decoding lands at `0x64b8d39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 218, column 31. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
