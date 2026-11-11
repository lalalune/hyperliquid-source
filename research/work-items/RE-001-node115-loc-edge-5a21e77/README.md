# RE-001: map node #115 l1/dex_registry/perp_dex.rs:29 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/perp_dex.rs` as an embedded path. At ELF VA `0x5a21e77` (file offset `0x5a20e77`), `4c8d058a1fa600` decodes as `lea r8, [rip + 0xa61f8a]`. Adding the signed displacement `10887050` to the next instruction VA `0x5a21e7e` yields `0x6483e08`. The decode from the start of FDE range `[0x5a21510, 0x5a21ed0)` reaches that instruction boundary. The FDE itself is at `0x13a1828`.

At `0x6483e08` (file offset `0x6481e08`), an `R_X86_64_RELATIVE` relocation points to `0x433bb6` in `.rodata`. The next 16 bytes, `1f000000000000001d0000001d000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 29 and 29. The string's normalized suffix matches `l1/dex_registry/perp_dex.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5a2161d` is `0x5a21e62` and the fallthrough is `0x5a21623`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r14, qword ptr [r12 + 0x3ad0]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a21615` | `4d3bb424d03a0000` | `cmp r14, qword ptr [r12 + 0x3ad0]` |
| `0x5a2161d` | `0f833f080000` | `jae 0x5a21e62` |
| `0x5a21e62` | `66c74424505601` | `mov word ptr [rsp + 0x50], 0x156` |
| `0x5a21e69` | `488d3d8a77dafa` | `lea rdi, [rip - 0x5258876]` |
| `0x5a21e70` | `488d0dc922a600` | `lea rcx, [rip + 0xa622c9]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 11261970 added to `0x5a21e8e` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a21e7e` | `488d542450` | `lea rdx, [rsp + 0x50]` |
| `0x5a21e83` | `be2b000000` | `mov esi, 0x2b` |
| `0x5a21e88` | `ff1512d8ab00` | `call qword ptr [rip + 0xabd812]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6483e08 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a21510 --stop-address=0x5a21e8e "$target"
od -An -tx1 -j 105389584 -N 16 "$target"
objdump -s -j .rodata --start-address=0x433bb6 --stop-address=0x433bd5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d058b1fa600`), re-decoding lands at `0x6483e09`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 29, column 29. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
