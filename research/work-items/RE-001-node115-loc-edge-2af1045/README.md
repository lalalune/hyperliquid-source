# RE-001: map node #115 node/startup.rs:122 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/startup.rs` as an embedded path. At ELF VA `0x2af1045` (file offset `0x2af0045`), `4c8d05dc6f9503` decodes as `lea r8, [rip + 0x3956fdc]`. Adding the signed displacement `60125148` to the next instruction VA `0x2af104c` yields `0x6448028`. The decode from the start of FDE range `[0x2af0660, 0x2af45e1)` reaches that instruction boundary. The FDE itself is at `0x117c600`.

At `0x6448028` (file offset `0x6446028`), an `R_X86_64_RELATIVE` relocation points to `0x438c81` in `.rodata`. The next 16 bytes, `13000000000000007a00000028000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 122 and 40. The string's normalized suffix matches `node/startup.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2af1019` establish a local edge into the argument setup. The taken target is `0x2af36c7` and the fallthrough is `0x2af101f`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2af1016` | `4885c0` | `test rax, rax` |
| `0x2af1019` | `0f84a8260000` | `je 0x2af36c7` |
| `0x2af101f` | `48c70001000000` | `mov qword ptr [rax], 1` |
| `0x2af1026` | `48c7400801000000` | `mov qword ptr [rax + 8], 1` |
| `0x2af102e` | `48896810` | `mov qword ptr [rax + 0x10], rbp` |
| `0x2af1032` | `4c896818` | `mov qword ptr [rax + 0x18], r13` |
| `0x2af1036` | `48896820` | `mov qword ptr [rax + 0x20], rbp` |
| `0x2af103a` | `4c897028` | `mov qword ptr [rax + 0x28], r14` |
| `0x2af103e` | `488d15714fb1fd` | `lea rdx, [rip - 0x24eb08f]` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -6220001 added to `0x2af1061` gives `0x2502780`. The target's FDE at `0x111cde4` describes `[0x2502780, 0x2502b4c)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2af104c` | `488dbc2410250000` | `lea rdi, [rsp + 0x2510]` |
| `0x2af1054` | `b919000000` | `mov ecx, 0x19` |
| `0x2af1059` | `4889c6` | `mov rsi, rax` |
| `0x2af105c` | `e81f17a1ff` | `call 0x2502780` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6448028 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2af0660 --stop-address=0x2af1061 "$target"
od -An -tx1 -j 105144368 -N 16 "$target"
objdump -s -j .rodata --start-address=0x438c81 --stop-address=0x438c94 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05dd6f9503`), re-decoding lands at `0x6448029`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 122, column 40. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
