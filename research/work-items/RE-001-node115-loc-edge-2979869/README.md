# RE-001: map node #115 info_server/abci_state_info_handler.rs:82 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x2979869` (file offset `0x2978869`), `4c8d057095ac03` decodes as `lea r8, [rip + 0x3ac9570]`. Adding the signed displacement `61642096` to the next instruction VA `0x2979870` yields `0x6442de0`. The decode from the start of FDE range `[0x2979800, 0x297990b)` reaches that instruction boundary. The FDE itself is at `0x115e05c`.

At `0x6442de0` (file offset `0x6440de0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000005200000010000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 82 and 16. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2979810` is `0x29798e7` and the fallthrough is `0x2979816`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x297980e` | `85c0` | `test eax, eax` |
| `0x2979810` | `0f85d1000000` | `jne 0x29798e7` |
| `0x2979816` | `4889f3` | `mov rbx, rsi` |
| `0x2979819` | `4989fe` | `mov r14, rdi` |
| `0x297981c` | `488b4630` | `mov rax, qword ptr [rsi + 0x30]` |
| `0x2979820` | `0f1006` | `movups xmm0, xmmword ptr [rsi]` |
| `0x2979823` | `0f104e10` | `movups xmm1, xmmword ptr [rsi + 0x10]` |
| `0x2979827` | `0f105620` | `movups xmm2, xmmword ptr [rsi + 0x20]` |
| `0x297982b` | `0f29542440` | `movaps xmmword ptr [rsp + 0x40], xmm2` |
| `0x2979830` | `0f294c2430` | `movaps xmmword ptr [rsp + 0x30], xmm1` |
| `0x2979835` | `0f29442420` | `movaps xmmword ptr [rsp + 0x20], xmm0` |
| `0x297983a` | `488b30` | `mov rsi, qword ptr [rax]` |
| `0x297983d` | `488d4610` | `lea rax, [rsi + 0x10]` |
| `0x2979841` | `0f104338` | `movups xmm0, xmmword ptr [rbx + 0x38]` |
| `0x2979845` | `0f11442410` | `movups xmmword ptr [rsp + 0x10], xmm0` |
| `0x297984a` | `48c744240800000000` | `mov qword ptr [rsp + 8], 0` |
| `0x2979853` | `4881c640010000` | `add rsi, 0x140` |
| `0x297985a` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x297985f` | `488d442408` | `lea rax, [rsp + 8]` |
| `0x2979864` | `4889442458` | `mov qword ptr [rsp + 0x58], rax` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed call displacement 340495 added to `0x2979881` gives `0x29cca90`. The target's FDE at `0x1162304` describes `[0x29cca90, 0x29cd44d)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2979870` | `488d7c2460` | `lea rdi, [rsp + 0x60]` |
| `0x2979875` | `488d542420` | `lea rdx, [rsp + 0x20]` |
| `0x297987a` | `31c9` | `xor ecx, ecx` |
| `0x297987c` | `e80f320500` | `call 0x29cca90` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6442de0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2979800 --stop-address=0x2979881 "$target"
od -An -tx1 -j 105123304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d057195ac03`), re-decoding lands at `0x6442de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 82, column 16. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
