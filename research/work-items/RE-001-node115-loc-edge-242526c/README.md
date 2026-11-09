# RE-001: map node #115 base/l1_map/entry.rs:210 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/l1_map/entry.rs` as an embedded path. At ELF VA `0x242526c` (file offset `0x242426c`), `488d1595a80004` decodes as `lea rdx, [rip + 0x400a895]`. Adding the signed displacement `67152021` to the next instruction VA `0x2425273` yields `0x642fb08`. The decode from the start of FDE range `[0x2425150, 0x242527e)` reaches that instruction boundary. The FDE itself is at `0xd0c9f4`.

At `0x642fb08` (file offset `0x642db08`), an `R_X86_64_RELATIVE` relocation points to `0x4402cd` in `.rodata`. The next 16 bytes, `1800000000000000d200000027000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 210 and 39. The string's normalized suffix matches `base/l1_map/entry.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2425180` is `0x2425265` and the fallthrough is `0x2425186`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r15, r8`. The recorded edge is selected when the `jbe` predicate (`CF = 1 or ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x242517d` | `4d39c7` | `cmp r15, r8` |
| `0x2425180` | `0f86df000000` | `jbe 0x2425265` |
| `0x2425265` | `488d3d078f1cfe` | `lea rdi, [rip - 0x1e370f9]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 67871986 added to `0x242527e` gives the relocation slot `0x64df770`. Its symbol-zero RELATIVE addend is `0x1680bd0`. The target's FDE at `0xcc2fec` describes `[0x1680bd0, 0x1680c04)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2425273` | `be14000000` | `mov esi, 0x14` |
| `0x2425278` | `ff15f2a40b04` | `call qword ptr [rip + 0x40ba4f2]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642fb08 '
readelf -rW "$target" | grep -i '0*64df770 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2425150 --stop-address=0x242527e "$target"
od -An -tx1 -j 105044752 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4402cd --stop-address=0x4402e5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1596a80004`), re-decoding lands at `0x642fb09`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 210, column 39. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
