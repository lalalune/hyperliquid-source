# RE-001: map node #115 info_server/abci_state_info_handler.rs:838 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x2a6a9a7` (file offset `0x2a699a7`), `488d0df2b99d03` decodes as `lea rcx, [rip + 0x39db9f2]`. Adding the signed displacement `60668402` to the next instruction VA `0x2a6a9ae` yields `0x64463a0`. The decode from the start of FDE range `[0x2a6a7e0, 0x2a6ab14)` reaches that instruction boundary. The FDE itself is at `0x116e66c`.

At `0x64463a0` (file offset `0x64443a0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000004603000029000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 838 and 41. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2a6a930` establish a local edge into the argument setup. The taken target is `0x2a6aa5e` and the fallthrough is `0x2a6a936`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `test rax, rax`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **false**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a6a92d` | `4885c0` | `test rax, rax` |
| `0x2a6a930` | `0f8428010000` | `je 0x2a6aa5e` |
| `0x2a6a936` | `0f10442458` | `movups xmm0, xmmword ptr [rsp + 0x58]` |
| `0x2a6a93b` | `0f114050` | `movups xmmword ptr [rax + 0x50], xmm0` |
| `0x2a6a93f` | `0f10442448` | `movups xmm0, xmmword ptr [rsp + 0x48]` |
| `0x2a6a944` | `0f114040` | `movups xmmword ptr [rax + 0x40], xmm0` |
| `0x2a6a948` | `0f10442408` | `movups xmm0, xmmword ptr [rsp + 8]` |
| `0x2a6a94d` | `0f104c2418` | `movups xmm1, xmmword ptr [rsp + 0x18]` |
| `0x2a6a952` | `0f10542428` | `movups xmm2, xmmword ptr [rsp + 0x28]` |
| `0x2a6a957` | `0f105c2438` | `movups xmm3, xmmword ptr [rsp + 0x38]` |
| `0x2a6a95c` | `0f115830` | `movups xmmword ptr [rax + 0x30], xmm3` |
| `0x2a6a960` | `0f115020` | `movups xmmword ptr [rax + 0x20], xmm2` |
| `0x2a6a964` | `0f114810` | `movups xmmword ptr [rax + 0x10], xmm1` |
| `0x2a6a968` | `0f1100` | `movups xmmword ptr [rax], xmm0` |
| `0x2a6a96b` | `488b7b18` | `mov rdi, qword ptr [rbx + 0x18]` |
| `0x2a6a96f` | `488d0d0d829cfd` | `lea rcx, [rip - 0x2637df3]` |
| `0x2a6a976` | `48894c2468` | `mov qword ptr [rsp + 0x68], rcx` |
| `0x2a6a97b` | `48c74424702a000000` | `mov qword ptr [rsp + 0x70], 0x2a` |
| `0x2a6a984` | `c744247846030000` | `mov dword ptr [rsp + 0x78], 0x346` |
| `0x2a6a98c` | `48897c2408` | `mov qword ptr [rsp + 8], rdi` |
| `0x2a6a991` | `4881c730010000` | `add rdi, 0x130` |
| `0x2a6a998` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x2a6a99d` | `488d442468` | `lea rax, [rsp + 0x68]` |
| `0x2a6a9a2` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -588138 added to `0x2a6a9ba` gives `0x29db050`. The target's FDE at `0x1162b74` describes `[0x29db050, 0x29db9ba)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a6a9ae` | `488d742408` | `lea rsi, [rsp + 8]` |
| `0x2a6a9b3` | `31d2` | `xor edx, edx` |
| `0x2a6a9b5` | `e89606f7ff` | `call 0x29db050` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64463a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2a6a7e0 --stop-address=0x2a6a9ba "$target"
od -An -tx1 -j 105137064 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0df3b99d03`), re-decoding lands at `0x64463a1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 838, column 41. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
