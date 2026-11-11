# RE-001: map node #115 l1/dex_registry/clearinghouses.rs:11 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/clearinghouses.rs` as an embedded path. At ELF VA `0x262ba45` (file offset `0x262aa45`), `4c8d0544ffe503` decodes as `lea r8, [rip + 0x3e5ff44]`. Adding the signed displacement `65404740` to the next instruction VA `0x262ba4c` yields `0x648b990`. The decode from the start of FDE range `[0x262aa00, 0x262bb67)` reaches that instruction boundary. The FDE itself is at `0x1125650`.

At `0x648b990` (file offset `0x6489990`), an `R_X86_64_RELATIVE` relocation points to `0x434c18` in `.rodata`. The next 16 bytes, `25000000000000000b0000001d000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 11 and 29. The string's normalized suffix matches `l1/dex_registry/clearinghouses.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x262b56a` is `0x262ba30` and the fallthrough is `0x262b570`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r12, qword ptr [rax + 0x7d0]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x262b563` | `4c3ba0d0070000` | `cmp r12, qword ptr [rax + 0x7d0]` |
| `0x262b56a` | `0f83c0040000` | `jae 0x262ba30` |
| `0x262ba30` | `66c74424105601` | `mov word ptr [rsp + 0x10], 0x156` |
| `0x262ba37` | `488d3dd4771afe` | `lea rdi, [rip - 0x1e5882c]` |
| `0x262ba3e` | `488d0db30be603` | `lea rcx, [rip + 0x3e60bb3]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 65748036 added to `0x262ba5c` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x262ba4c` | `488d542410` | `lea rdx, [rsp + 0x10]` |
| `0x262ba51` | `be2b000000` | `mov esi, 0x2b` |
| `0x262ba56` | `ff15443ceb03` | `call qword ptr [rip + 0x3eb3c44]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b990 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x262aa00 --stop-address=0x262ba5c "$target"
od -An -tx1 -j 105421208 -N 16 "$target"
objdump -s -j .rodata --start-address=0x434c18 --stop-address=0x434c3d "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0545ffe503`), re-decoding lands at `0x648b991`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 11, column 29. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
