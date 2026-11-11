# RE-001: map node #115 info_server/abci_state_info_handler.rs:82 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x2978f8f` (file offset `0x2977f8f`), `488d0d4a9eac03` decodes as `lea rcx, [rip + 0x3ac9e4a]`. Adding the signed displacement `61644362` to the next instruction VA `0x2978f96` yields `0x6442de0`. The decode from the start of FDE range `[0x2978f40, 0x2978fd0)` reaches that instruction boundary. The FDE itself is at `0x115de3c`.

At `0x6442de0` (file offset `0x6440de0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000005200000010000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 82 and 16. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2978f4b` is `0x2978fac` and the fallthrough is `0x2978f4d`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2978f49` | `85c0` | `test eax, eax` |
| `0x2978f4b` | `755f` | `jne 0x2978fac` |
| `0x2978f4d` | `4889fb` | `mov rbx, rdi` |
| `0x2978f50` | `488b07` | `mov rax, qword ptr [rdi]` |
| `0x2978f53` | `8b4f28` | `mov ecx, dword ptr [rdi + 0x28]` |
| `0x2978f56` | `894c2438` | `mov dword ptr [rsp + 0x38], ecx` |
| `0x2978f5a` | `0f104718` | `movups xmm0, xmmword ptr [rdi + 0x18]` |
| `0x2978f5e` | `0f11442428` | `movups xmmword ptr [rsp + 0x28], xmm0` |
| `0x2978f63` | `488b38` | `mov rdi, qword ptr [rax]` |
| `0x2978f66` | `488d4710` | `lea rax, [rdi + 0x10]` |
| `0x2978f6a` | `0f104308` | `movups xmm0, xmmword ptr [rbx + 8]` |
| `0x2978f6e` | `0f11442408` | `movups xmmword ptr [rsp + 8], xmm0` |
| `0x2978f73` | `48c7042400000000` | `mov qword ptr [rsp], 0` |
| `0x2978f7b` | `4881c740010000` | `add rdi, 0x140` |
| `0x2978f82` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x2978f87` | `4889e0` | `mov rax, rsp` |
| `0x2978f8a` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed call displacement 406414 added to `0x2978fa2` gives `0x29dc330`. The target's FDE at `0x1162c34` describes `[0x29dc330, 0x29dcc67)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2978f96` | `488d742418` | `lea rsi, [rsp + 0x18]` |
| `0x2978f9b` | `31d2` | `xor edx, edx` |
| `0x2978f9d` | `e88e330600` | `call 0x29dc330` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6442de0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2978f40 --stop-address=0x2978fa2 "$target"
od -An -tx1 -j 105123304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d4b9eac03`), re-decoding lands at `0x6442de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 82, column 16. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
