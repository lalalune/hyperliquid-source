# RE-001: map node #115 node/hl_node.rs:322 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/hl_node.rs` as an embedded path. At ELF VA `0x2cac9b5` (file offset `0x2cab9b5`), `4c8d0584177a03` decodes as `lea r8, [rip + 0x37a1784]`. Adding the signed displacement `58333060` to the next instruction VA `0x2cac9bc` yields `0x644e140`. The decode from the start of FDE range `[0x2cac980, 0x2cac9e9)` reaches that instruction boundary. The FDE itself is at `0x11966e8`.

At `0x644e140` (file offset `0x644c140`), an `R_X86_64_RELATIVE` relocation points to `0x436a23` in `.rodata`. The next 16 bytes, `1300000000000000420100003f000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 322 and 63. The string's normalized suffix matches `node/hl_node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2cac988` is `0x2cac99e` and the fallthrough is `0x2cac98a`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp dword ptr [rsi], 1`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2cac985` | `833e01` | `cmp dword ptr [rsi], 1` |
| `0x2cac988` | `7414` | `je 0x2cac99e` |
| `0x2cac99e` | `488b4608` | `mov rax, qword ptr [rsi + 8]` |
| `0x2cac9a2` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x2cac9a7` | `488d3d212796fd` | `lea rdi, [rip - 0x269d8df]` |
| `0x2cac9ae` | `488d0d23137a03` | `lea rcx, [rip + 0x37a1323]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 58928340 added to `0x2cac9cc` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2cac9bc` | `488d542408` | `lea rdx, [rsp + 8]` |
| `0x2cac9c1` | `be1c000000` | `mov esi, 0x1c` |
| `0x2cac9c6` | `ff15d42c8303` | `call qword ptr [rip + 0x3832cd4]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644e140 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2cac980 --stop-address=0x2cac9cc "$target"
od -An -tx1 -j 105169224 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436a23 --stop-address=0x436a36 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0585177a03`), re-decoding lands at `0x644e141`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 322, column 63. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
