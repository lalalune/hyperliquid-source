# RE-001: map node #115 node/nv_stream.rs:342 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/nv_stream.rs` as an embedded path. At ELF VA `0x5a817a8` (file offset `0x5a807a8`), `4c8d059179a300` decodes as `lea r8, [rip + 0xa37991]`. Adding the signed displacement `10713489` to the next instruction VA `0x5a817af` yields `0x64b9140`. The decode from the start of FDE range `[0x5a81650, 0x5a81ec8)` reaches that instruction boundary. The FDE itself is at `0x13aa840`.

At `0x64b9140` (file offset `0x64b7140`), an `R_X86_64_RELATIVE` relocation points to `0x43bce4` in `.rodata`. The next 16 bytes, `1500000000000000560100001b000000`, decode as a little-endian 64-bit length of 21 and two 32-bit values, 342 and 27. The string's normalized suffix matches `node/nv_stream.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `jbe` and conditional jump at `0x5a81681` establish a local edge into the argument setup. The taken target is `0x5a81775` and the fallthrough is `0x5a81687`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `cmp rax, qword ptr [rsi + 0x110]`. The recorded edge reaches the load when the `jbe` predicate (`CF = 1 or ZF = 1`) is **true**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a8167a` | `483b8610010000` | `cmp rax, qword ptr [rsi + 0x110]` |
| `0x5a81681` | `0f86ee000000` | `jbe 0x5a81775` |
| `0x5a81775` | `4989f6` | `mov r14, rsi` |
| `0x5a81778` | `488bbef8000000` | `mov rdi, qword ptr [rsi + 0xf8]` |
| `0x5a8177f` | `488d7710` | `lea rsi, [rdi + 0x10]` |
| `0x5a81783` | `488d0590a1ebfa` | `lea rax, [rip - 0x5145e70]` |
| `0x5a8178a` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x5a8178f` | `48c744242014000000` | `mov qword ptr [rsp + 0x20], 0x14` |
| `0x5a81798` | `48c744241000000000` | `mov qword ptr [rsp + 0x10], 0` |
| `0x5a817a1` | `4881c740010000` | `add rdi, 0x140` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -11973019 added to `0x5a817bb` gives `0x4f16620`. The target's FDE at `0x130ad64` describes `[0x4f16620, 0x4f16fa3)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a817af` | `488d542410` | `lea rdx, [rsp + 0x10]` |
| `0x5a817b4` | `31c9` | `xor ecx, ecx` |
| `0x5a817b6` | `e8654e49ff` | `call 0x4f16620` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b9140 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a81650 --stop-address=0x5a817bb "$target"
od -An -tx1 -j 105607496 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43bce4 --stop-address=0x43bcf9 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d059279a300`), re-decoding lands at `0x64b9141`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 342, column 27. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
