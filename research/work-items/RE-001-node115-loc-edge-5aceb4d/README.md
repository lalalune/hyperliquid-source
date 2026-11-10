# RE-001: map node #115 l1/dex_registry/perp_dex.rs:34 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/perp_dex.rs` as an embedded path. At ELF VA `0x5aceb4d` (file offset `0x5acdb4d`), `4c8d05cc529b00` decodes as `lea r8, [rip + 0x9b52cc]`. Adding the signed displacement `10179276` to the next instruction VA `0x5aceb54` yields `0x6483e20`. The decode from the start of FDE range `[0x5ace710, 0x5acec03)` reaches that instruction boundary. The FDE itself is at `0x13aef00`.

At `0x6483e20` (file offset `0x6481e20`), an `R_X86_64_RELATIVE` relocation points to `0x433bb6` in `.rodata`. The next 16 bytes, `1f000000000000002200000021000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 34 and 33. The string's normalized suffix matches `l1/dex_registry/perp_dex.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5ace9f9` is `0x5aceb38` and the fallthrough is `0x5ace9ff`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r12, qword ptr [rax + 0x10]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5ace9f5` | `4c3b6010` | `cmp r12, qword ptr [rax + 0x10]` |
| `0x5ace9f9` | `0f8339010000` | `jae 0x5aceb38` |
| `0x5aceb38` | `66c74424405601` | `mov word ptr [rsp + 0x40], 0x156` |
| `0x5aceb3f` | `488d3db4aacffa` | `lea rdi, [rip - 0x530554c]` |
| `0x5aceb46` | `488d0df3559b00` | `lea rcx, [rip + 0x9b55f3]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 10554172 added to `0x5aceb64` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5aceb54` | `488d542440` | `lea rdx, [rsp + 0x40]` |
| `0x5aceb59` | `be2b000000` | `mov esi, 0x2b` |
| `0x5aceb5e` | `ff153c0ba100` | `call qword ptr [rip + 0xa10b3c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6483e20 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5ace710 --stop-address=0x5aceb64 "$target"
od -An -tx1 -j 105389608 -N 16 "$target"
objdump -s -j .rodata --start-address=0x433bb6 --stop-address=0x433bd5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05cd529b00`), re-decoding lands at `0x6483e21`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 34, column 33. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
