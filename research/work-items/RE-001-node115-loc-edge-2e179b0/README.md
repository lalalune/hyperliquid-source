# RE-001: map node #115 node/consensus/mempool.rs:516 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/consensus/mempool.rs` as an embedded path. At ELF VA `0x2e179b0` (file offset `0x2e169b0`), `488d1501a26303` decodes as `lea rdx, [rip + 0x363a201]`. Adding the signed displacement `56861185` to the next instruction VA `0x2e179b7` yields `0x6451bb8`. The decode from the start of FDE range `[0x2e157c0, 0x2e197f5)` reaches that instruction boundary. The FDE itself is at `0x11b22a4`.

At `0x6451bb8` (file offset `0x644fbb8`), an `R_X86_64_RELATIVE` relocation points to `0x44f69a` in `.rodata`. The next 16 bytes, `1d000000000000000402000026000000`, decode as a little-endian 64-bit length of 29 and two 32-bit values, 516 and 38. The string's normalized suffix matches `node/consensus/mempool.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `jne` and conditional jump at `0x2e1796f` establish a local edge into the argument setup. The taken target is `0x2e17987` and the fallthrough is `0x2e17971`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2e17967` | `48398c2450040000` | `cmp qword ptr [rsp + 0x450], rcx` |
| `0x2e1796f` | `7516` | `jne 0x2e17987` |
| `0x2e17987` | `8b4830` | `mov ecx, dword ptr [rax + 0x30]` |
| `0x2e1798a` | `898c2430040000` | `mov dword ptr [rsp + 0x430], ecx` |
| `0x2e17991` | `660f104020` | `movupd xmm0, xmmword ptr [rax + 0x20]` |
| `0x2e17996` | `660f29842420040000` | `movapd xmmword ptr [rsp + 0x420], xmm0` |
| `0x2e1799f` | `488b5818` | `mov rbx, qword ptr [rax + 0x18]` |
| `0x2e179a3` | `488b7c2430` | `mov rdi, qword ptr [rsp + 0x30]` |
| `0x2e179a8` | `488db42430060000` | `lea rsi, [rsp + 0x630]` |

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -1484428 added to `0x2e179bc` gives `0x2cad330`. The target's FDE at `0xd8b0fc` describes `[0x2cad330, 0x2cad58a)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2e179b7` | `e87459e9ff` | `call 0x2cad330` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6451bb8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2e157c0 --stop-address=0x2e179bc "$target"
od -An -tx1 -j 105184192 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f69a --stop-address=0x44f6b7 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1502a26303`), re-decoding lands at `0x6451bb9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 516, column 38. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
