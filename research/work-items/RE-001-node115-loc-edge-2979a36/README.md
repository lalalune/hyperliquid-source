# RE-001: map node #115 info_server/abci_state_info_handler.rs:82 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x2979a36` (file offset `0x2978a36`), `488d0da393ac03` decodes as `lea rcx, [rip + 0x3ac93a3]`. Adding the signed displacement `61641635` to the next instruction VA `0x2979a3d` yields `0x6442de0`. The decode from the start of FDE range `[0x29799d0, 0x2979a79)` reaches that instruction boundary. The FDE itself is at `0x115e0c4`.

At `0x6442de0` (file offset `0x6440de0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000005200000010000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 82 and 16. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x29799db` is `0x2979a55` and the fallthrough is `0x29799dd`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x29799d9` | `85c0` | `test eax, eax` |
| `0x29799db` | `7578` | `jne 0x2979a55` |
| `0x29799dd` | `4889fb` | `mov rbx, rdi` |
| `0x29799e0` | `488b4740` | `mov rax, qword ptr [rdi + 0x40]` |
| `0x29799e4` | `0f1007` | `movups xmm0, xmmword ptr [rdi]` |
| `0x29799e7` | `0f104f10` | `movups xmm1, xmmword ptr [rdi + 0x10]` |
| `0x29799eb` | `0f105720` | `movups xmm2, xmmword ptr [rdi + 0x20]` |
| `0x29799ef` | `0f105f30` | `movups xmm3, xmmword ptr [rdi + 0x30]` |
| `0x29799f3` | `0f295c2450` | `movaps xmmword ptr [rsp + 0x50], xmm3` |
| `0x29799f8` | `0f29542440` | `movaps xmmword ptr [rsp + 0x40], xmm2` |
| `0x29799fd` | `0f294c2430` | `movaps xmmword ptr [rsp + 0x30], xmm1` |
| `0x2979a02` | `0f29442420` | `movaps xmmword ptr [rsp + 0x20], xmm0` |
| `0x2979a07` | `488b38` | `mov rdi, qword ptr [rax]` |
| `0x2979a0a` | `488d4710` | `lea rax, [rdi + 0x10]` |
| `0x2979a0e` | `0f104348` | `movups xmm0, xmmword ptr [rbx + 0x48]` |
| `0x2979a12` | `0f11442410` | `movups xmmword ptr [rsp + 0x10], xmm0` |
| `0x2979a17` | `48c744240800000000` | `mov qword ptr [rsp + 8], 0` |
| `0x2979a20` | `4881c740010000` | `add rdi, 0x140` |
| `0x2979a27` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x2979a2c` | `488d442408` | `lea rax, [rsp + 8]` |
| `0x2979a31` | `4889442468` | `mov qword ptr [rsp + 0x68], rax` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed call displacement 362183 added to `0x2979a49` gives `0x29d2110`. The target's FDE at `0x1162610` describes `[0x29d2110, 0x29d2ae7)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2979a3d` | `488d742420` | `lea rsi, [rsp + 0x20]` |
| `0x2979a42` | `31d2` | `xor edx, edx` |
| `0x2979a44` | `e8c7860500` | `call 0x29d2110` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6442de0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x29799d0 --stop-address=0x2979a49 "$target"
od -An -tx1 -j 105123304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0da493ac03`), re-decoding lands at `0x6442de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 82, column 16. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
