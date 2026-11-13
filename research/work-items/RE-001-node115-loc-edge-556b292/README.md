# RE-001: map node #115 l1/dex_registry/clearinghouses.rs:17 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/clearinghouses.rs` as an embedded path. At ELF VA `0x556b292` (file offset `0x556a292`), `4c8d050f07f200` decodes as `lea r8, [rip + 0xf2070f]`. Adding the signed displacement `15861519` to the next instruction VA `0x556b299` yields `0x648b9a8`. The decode from the start of FDE range `[0x556ab20, 0x556b394)` reaches that instruction boundary. The FDE itself is at `0x1359950`.

At `0x648b9a8` (file offset `0x64899a8`), an `R_X86_64_RELATIVE` relocation points to `0x434c18` in `.rodata`. The next 16 bytes, `25000000000000001100000021000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 17 and 33. The string's normalized suffix matches `l1/dex_registry/clearinghouses.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x556af8e` is `0x556b27d` and the fallthrough is `0x556af94`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r13, qword ptr [r14 + 0x7d0]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x556af87` | `4d3baed0070000` | `cmp r13, qword ptr [r14 + 0x7d0]` |
| `0x556af8e` | `0f83e9020000` | `jae 0x556b27d` |
| `0x556b27d` | `66c74424405601` | `mov word ptr [rsp + 0x40], 0x156` |
| `0x556b284` | `488d3d877f26fb` | `lea rdi, [rip - 0x4d98079]` |
| `0x556b28b` | `488d0d6613f200` | `lea rcx, [rip + 0xf21366]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 16204791 added to `0x556b2a9` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x556b299` | `488d542440` | `lea rdx, [rsp + 0x40]` |
| `0x556b29e` | `be2b000000` | `mov esi, 0x2b` |
| `0x556b2a3` | `ff15f743f700` | `call qword ptr [rip + 0xf743f7]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b9a8 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x556ab20 --stop-address=0x556b2a9 "$target"
od -An -tx1 -j 105421232 -N 16 "$target"
objdump -s -j .rodata --start-address=0x434c18 --stop-address=0x434c3d "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d051007f200`), re-decoding lands at `0x648b9a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 17, column 33. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
