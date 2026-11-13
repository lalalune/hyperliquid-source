# RE-001: map node #115 l1/dex_registry/clearinghouses.rs:17 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/clearinghouses.rs` as an embedded path. At ELF VA `0x54ca551` (file offset `0x54c9551`), `4c8d055014fc00` decodes as `lea r8, [rip + 0xfc1450]`. Adding the signed displacement `16520272` to the next instruction VA `0x54ca558` yields `0x648b9a8`. The decode from the start of FDE range `[0x54ca190, 0x54ca6a1)` reaches that instruction boundary. The FDE itself is at `0x1353f34`.

At `0x648b9a8` (file offset `0x64899a8`), an `R_X86_64_RELATIVE` relocation points to `0x434c18` in `.rodata`. The next 16 bytes, `25000000000000001100000021000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 17 and 33. The string's normalized suffix matches `l1/dex_registry/clearinghouses.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x54ca355` is `0x54ca53c` and the fallthrough is `0x54ca35b`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r14, qword ptr [rbx + 0x7d0]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54ca34e` | `4c3bb3d0070000` | `cmp r14, qword ptr [rbx + 0x7d0]` |
| `0x54ca355` | `0f83e1010000` | `jae 0x54ca53c` |
| `0x54ca53c` | `66c74424605601` | `mov word ptr [rsp + 0x60], 0x156` |
| `0x54ca543` | `488d3dc88c30fb` | `lea rdi, [rip - 0x4cf7338]` |
| `0x54ca54a` | `488d0da720fc00` | `lea rcx, [rip + 0xfc20a7]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 16863544 added to `0x54ca568` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54ca558` | `488d542460` | `lea rdx, [rsp + 0x60]` |
| `0x54ca55d` | `be2b000000` | `mov esi, 0x2b` |
| `0x54ca562` | `ff1538510101` | `call qword ptr [rip + 0x1015138]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b9a8 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x54ca190 --stop-address=0x54ca568 "$target"
od -An -tx1 -j 105421232 -N 16 "$target"
objdump -s -j .rodata --start-address=0x434c18 --stop-address=0x434c3d "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d055114fc00`), re-decoding lands at `0x648b9a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 17, column 33. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
