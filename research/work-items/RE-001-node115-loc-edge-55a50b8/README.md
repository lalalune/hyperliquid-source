# RE-001: map node #115 l1/dex_registry/perp_dex.rs:34 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/perp_dex.rs` as an embedded path. At ELF VA `0x55a50b8` (file offset `0x55a40b8`), `4c8d0561eded00` decodes as `lea r8, [rip + 0xeded61]`. Adding the signed displacement `15592801` to the next instruction VA `0x55a50bf` yields `0x6483e20`. The decode from the start of FDE range `[0x55a47f0, 0x55a51b0)` reaches that instruction boundary. The FDE itself is at `0x135bc24`.

At `0x6483e20` (file offset `0x6481e20`), an `R_X86_64_RELATIVE` relocation points to `0x433bb6` in `.rodata`. The next 16 bytes, `1f000000000000002200000021000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 34 and 33. The string's normalized suffix matches `l1/dex_registry/perp_dex.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x55a501d` is `0x55a50a3` and the fallthrough is `0x55a5023`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r13, rbx`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55a501a` | `4939dd` | `cmp r13, rbx` |
| `0x55a501d` | `0f8380000000` | `jae 0x55a50a3` |
| `0x55a50a3` | `66c74424405601` | `mov word ptr [rsp + 0x40], 0x156` |
| `0x55a50aa` | `488d3d494522fb` | `lea rdi, [rip - 0x4ddbab7]` |
| `0x55a50b1` | `488d0d88f0ed00` | `lea rcx, [rip + 0xedf088]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 15967697 added to `0x55a50cf` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55a50bf` | `488d542440` | `lea rdx, [rsp + 0x40]` |
| `0x55a50c4` | `be2b000000` | `mov esi, 0x2b` |
| `0x55a50c9` | `ff15d1a5f300` | `call qword ptr [rip + 0xf3a5d1]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6483e20 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x55a47f0 --stop-address=0x55a50cf "$target"
od -An -tx1 -j 105389608 -N 16 "$target"
objdump -s -j .rodata --start-address=0x433bb6 --stop-address=0x433bd5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0562eded00`), re-decoding lands at `0x6483e21`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 34, column 33. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
