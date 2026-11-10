# RE-001: map node #115 info_server/abci_state_info_handler.rs:82 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x297a19a` (file offset `0x297919a`), `488d0d3f8cac03` decodes as `lea rcx, [rip + 0x3ac8c3f]`. Adding the signed displacement `61639743` to the next instruction VA `0x297a1a1` yields `0x6442de0`. The decode from the start of FDE range `[0x297a140, 0x297a1e0)` reaches that instruction boundary. The FDE itself is at `0x115e288`.

At `0x6442de0` (file offset `0x6440de0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000005200000010000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 82 and 16. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x297a14b` is `0x297a1bc` and the fallthrough is `0x297a14d`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x297a149` | `85c0` | `test eax, eax` |
| `0x297a14b` | `756f` | `jne 0x297a1bc` |
| `0x297a14d` | `4889fb` | `mov rbx, rdi` |
| `0x297a150` | `488b07` | `mov rax, qword ptr [rdi]` |
| `0x297a153` | `488b4f38` | `mov rcx, qword ptr [rdi + 0x38]` |
| `0x297a157` | `48894c2448` | `mov qword ptr [rsp + 0x48], rcx` |
| `0x297a15c` | `0f104718` | `movups xmm0, xmmword ptr [rdi + 0x18]` |
| `0x297a160` | `0f104f28` | `movups xmm1, xmmword ptr [rdi + 0x28]` |
| `0x297a164` | `0f114c2438` | `movups xmmword ptr [rsp + 0x38], xmm1` |
| `0x297a169` | `0f11442428` | `movups xmmword ptr [rsp + 0x28], xmm0` |
| `0x297a16e` | `488b38` | `mov rdi, qword ptr [rax]` |
| `0x297a171` | `488d4710` | `lea rax, [rdi + 0x10]` |
| `0x297a175` | `0f104308` | `movups xmm0, xmmword ptr [rbx + 8]` |
| `0x297a179` | `0f11442408` | `movups xmmword ptr [rsp + 8], xmm0` |
| `0x297a17e` | `48c7042400000000` | `mov qword ptr [rsp], 0` |
| `0x297a186` | `4881c740010000` | `add rdi, 0x140` |
| `0x297a18d` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x297a192` | `4889e0` | `mov rax, rsp` |
| `0x297a195` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed call displacement 348067 added to `0x297a1ad` gives `0x29cf150`. The target's FDE at `0x1162454` describes `[0x29cf150, 0x29cfa89)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x297a1a1` | `488d742418` | `lea rsi, [rsp + 0x18]` |
| `0x297a1a6` | `31d2` | `xor edx, edx` |
| `0x297a1a8` | `e8a34f0500` | `call 0x29cf150` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6442de0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x297a140 --stop-address=0x297a1ad "$target"
od -An -tx1 -j 105123304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d408cac03`), re-decoding lands at `0x6442de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 82, column 16. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
