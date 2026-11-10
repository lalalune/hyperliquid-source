# RE-001: map node #115 base/wallet.rs:38 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/wallet.rs` as an embedded path. At ELF VA `0x44fe913` (file offset `0x44fd913`), `4c8d059ef3f701` decodes as `lea r8, [rip + 0x1f7f39e]`. Adding the signed displacement `33026974` to the next instruction VA `0x44fe91a` yields `0x647dcb8`. The decode from the start of FDE range `[0x44fe850, 0x44fe943)` reaches that instruction boundary. The FDE itself is at `0x12a8f30`.

At `0x647dcb8` (file offset `0x647bcb8`), an `R_X86_64_RELATIVE` relocation points to `0x4388f2` in `.rodata`. The next 16 bytes, `12000000000000002600000037000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 38 and 55. The string's normalized suffix matches `base/wallet.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x44fe8c4` is `0x44fe8f2` and the fallthrough is `0x44fe8c6`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp byte ptr [rsp + 0x20], 1`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44fe8bf` | `807c242001` | `cmp byte ptr [rsp + 0x20], 1` |
| `0x44fe8c4` | `742c` | `je 0x44fe8f2` |
| `0x44fe8f2` | `488b442438` | `mov rax, qword ptr [rsp + 0x38]` |
| `0x44fe8f7` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x44fe8fc` | `0f10442428` | `movups xmm0, xmmword ptr [rsp + 0x28]` |
| `0x44fe901` | `0f290424` | `movaps xmmword ptr [rsp], xmm0` |
| `0x44fe905` | `488d3d69792cfc` | `lea rdi, [rip - 0x3d38697]` |
| `0x44fe90c` | `488d0dbdf3f701` | `lea rcx, [rip + 0x1f7f3bd]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 33426808 added to `0x44fe928` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44fe91a` | `4889e2` | `mov rdx, rsp` |
| `0x44fe91d` | `be2b000000` | `mov esi, 0x2b` |
| `0x44fe922` | `ff15780dfe01` | `call qword ptr [rip + 0x1fe0d78]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*647dcb8 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x44fe850 --stop-address=0x44fe928 "$target"
od -An -tx1 -j 105364672 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4388f2 --stop-address=0x438904 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d059ff3f701`), re-decoding lands at `0x647dcb9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 38, column 55. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
