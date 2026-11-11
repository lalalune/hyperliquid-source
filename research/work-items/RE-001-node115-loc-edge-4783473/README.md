# RE-001: map node #115 base/lu.rs:215 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/lu.rs` as an embedded path. At ELF VA `0x4783473` (file offset `0x4782473`), `4c8d0506e0c701` decodes as `lea r8, [rip + 0x1c7e006]`. Adding the signed displacement `29876230` to the next instruction VA `0x478347a` yields `0x6401480`. The decode from the start of FDE range `[0x47833c0, 0x47834be)` reaches that instruction boundary. The FDE itself is at `0x12c880c`.

At `0x6401480` (file offset `0x63ff480`), an `R_X86_64_RELATIVE` relocation points to `0x4326c1` in `.rodata`. The next 16 bytes, `0e00000000000000d700000024000000`, decode as a little-endian 64-bit length of 14 and two 32-bit values, 215 and 36. The string's normalized suffix matches `base/lu.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4783417` is `0x4783456` and the fallthrough is `0x4783419`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4783415` | `85c0` | `test eax, eax` |
| `0x4783417` | `753d` | `jne 0x4783456` |
| `0x4783456` | `c644240f01` | `mov byte ptr [rsp + 0xf], 1` |
| `0x478345b` | `488d44240f` | `lea rax, [rsp + 0xf]` |
| `0x4783460` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x4783465` | `488d3d6ccfd601` | `lea rdi, [rip + 0x1d6cf6c]` |
| `0x478346c` | `488d0d8dddc701` | `lea rcx, [rip + 0x1c7dd8d]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 30786921 added to `0x4783487` gives the relocation slot `0x64df9f0`. Its symbol-zero RELATIVE addend is `0x5c87d50`. The target's FDE at `0x13ccad4` describes `[0x5c87d50, 0x5c87f6c)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x478347a` | `488d542410` | `lea rdx, [rsp + 0x10]` |
| `0x478347f` | `31f6` | `xor esi, esi` |
| `0x4783481` | `ff1569c5d501` | `call qword ptr [rip + 0x1d5c569]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6401480 '
readelf -rW "$target" | grep -i '0*64df9f0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x47833c0 --stop-address=0x4783487 "$target"
od -An -tx1 -j 104854664 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4326c1 --stop-address=0x4326cf "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0507e0c701`), re-decoding lands at `0x6401481`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 215, column 36. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
