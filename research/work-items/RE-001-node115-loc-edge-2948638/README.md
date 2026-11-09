# RE-001: map node #115 l1/dex_registry/clearinghouses.rs:11 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/clearinghouses.rs` as an embedded path. At ELF VA `0x2948638` (file offset `0x2947638`), `4c8d055133b403` decodes as `lea r8, [rip + 0x3b43351]`. Adding the signed displacement `62141265` to the next instruction VA `0x294863f` yields `0x648b990`. The decode from the start of FDE range `[0x2947ff0, 0x29486f9)` reaches that instruction boundary. The FDE itself is at `0x115b038`.

At `0x648b990` (file offset `0x6489990`), an `R_X86_64_RELATIVE` relocation points to `0x434c18` in `.rodata`. The next 16 bytes, `25000000000000000b0000001d000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 11 and 29. The string's normalized suffix matches `l1/dex_registry/clearinghouses.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2948229` is `0x2948624` and the fallthrough is `0x294822f`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rax, qword ptr [r14 + 0x7d0]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2948222` | `493b86d0070000` | `cmp rax, qword ptr [r14 + 0x7d0]` |
| `0x2948229` | `0f83f5030000` | `jae 0x2948624` |
| `0x2948624` | `66c704245601` | `mov word ptr [rsp], 0x156` |
| `0x294862a` | `488d3de1abe8fd` | `lea rdi, [rip - 0x217541f]` |
| `0x2948631` | `488d0dc03fb403` | `lea rcx, [rip + 0x3b43fc0]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 62484563 added to `0x294864d` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x294863f` | `4889e2` | `mov rdx, rsp` |
| `0x2948642` | `be2b000000` | `mov esi, 0x2b` |
| `0x2948647` | `ff155370b903` | `call qword ptr [rip + 0x3b97053]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b990 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2947ff0 --stop-address=0x294864d "$target"
od -An -tx1 -j 105421208 -N 16 "$target"
objdump -s -j .rodata --start-address=0x434c18 --stop-address=0x434c3d "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d055233b403`), re-decoding lands at `0x648b991`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 11, column 29. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
