# RE-001: map node #115 base/liner.rs:28 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/liner.rs` as an embedded path. At ELF VA `0x14c3bd9` (file offset `0x14c2bd9`), `4c8d054852f304` decodes as `lea r8, [rip + 0x4f35248]`. Adding the signed displacement `83055176` to the next instruction VA `0x14c3be0` yields `0x63f8e28`. The decode from the start of FDE range `[0x14c3b30, 0x14c3c86)` reaches that instruction boundary. The FDE itself is at `0x1046f38`.

At `0x63f8e28` (file offset `0x63f6e28`), an `R_X86_64_RELATIVE` relocation points to `0x44a81e` in `.rodata`. The next 16 bytes, `11000000000000001c00000026000000`, decode as a little-endian 64-bit length of 17 and two 32-bit values, 28 and 38. The string's normalized suffix matches `base/liner.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x14c3b5a` is `0x14c3bc7` and the fallthrough is `0x14c3b5c`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x14c3b57` | `4885c0` | `test rax, rax` |
| `0x14c3b5a` | `756b` | `jne 0x14c3bc7` |
| `0x14c3bc7` | `48890424` | `mov qword ptr [rsp], rax` |
| `0x14c3bcb` | `488d3df80dfafe` | `lea rdi, [rip - 0x105f208]` |
| `0x14c3bd2` | `488d0da752f304` | `lea rcx, [rip + 0x4f352a7]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 83999410 added to `0x14c3bee` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x14c3be0` | `4889e2` | `mov rdx, rsp` |
| `0x14c3be3` | `be2b000000` | `mov esi, 0x2b` |
| `0x14c3be8` | `ff15b2ba0105` | `call qword ptr [rip + 0x501bab2]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63f8e28 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x14c3b30 --stop-address=0x14c3bee "$target"
od -An -tx1 -j 104820272 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44a81e --stop-address=0x44a82f "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d054952f304`), re-decoding lands at `0x63f8e29`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 28, column 38. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
