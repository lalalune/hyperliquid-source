# RE-001: map node #115 base/lu.rs:215 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/lu.rs` as an embedded path. At ELF VA `0x5a7b267` (file offset `0x5a7a267`), `4c8d0512629800` decodes as `lea r8, [rip + 0x986212]`. Adding the signed displacement `9986578` to the next instruction VA `0x5a7b26e` yields `0x6401480`. The decode from the start of FDE range `[0x5a7b160, 0x5a7b2b2)` reaches that instruction boundary. The FDE itself is at `0x13aa4e4`.

At `0x6401480` (file offset `0x63ff480`), an `R_X86_64_RELATIVE` relocation points to `0x4326c1` in `.rodata`. The next 16 bytes, `0e00000000000000d700000024000000`, decode as a little-endian 64-bit length of 14 and two 32-bit values, 215 and 36. The string's normalized suffix matches `base/lu.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5a7b20a` is `0x5a7b24a` and the fallthrough is `0x5a7b20c`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a7b208` | `85c0` | `test eax, eax` |
| `0x5a7b20a` | `753e` | `jne 0x5a7b24a` |
| `0x5a7b24a` | `c644240701` | `mov byte ptr [rsp + 7], 1` |
| `0x5a7b24f` | `488d442407` | `lea rax, [rsp + 7]` |
| `0x5a7b254` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x5a7b259` | `488d3d7851a700` | `lea rdi, [rip + 0xa75178]` |
| `0x5a7b260` | `488d0d995f9800` | `lea rcx, [rip + 0x985f99]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 10897269 added to `0x5a7b27b` gives the relocation slot `0x64df9f0`. Its symbol-zero RELATIVE addend is `0x5c87d50`. The target's FDE at `0x13ccad4` describes `[0x5c87d50, 0x5c87f6c)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a7b26e` | `488d542408` | `lea rdx, [rsp + 8]` |
| `0x5a7b273` | `31f6` | `xor esi, esi` |
| `0x5a7b275` | `ff157547a600` | `call qword ptr [rip + 0xa64775]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6401480 '
readelf -rW "$target" | grep -i '0*64df9f0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a7b160 --stop-address=0x5a7b27b "$target"
od -An -tx1 -j 104854664 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4326c1 --stop-address=0x4326cf "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0513629800`), re-decoding lands at `0x6401481`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 215, column 36. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
