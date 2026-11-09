# RE-001: map node #115 l1/spot_meta.rs:125 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/spot_meta.rs` as an embedded path. At ELF VA `0x2c540a9` (file offset `0x2c530a9`), `488d3d40288203` decodes as `lea rdi, [rip + 0x3822840]`. Adding the signed displacement `58861632` to the next instruction VA `0x2c540b0` yields `0x64768f0`. The decode from the start of FDE range `[0x2c53850, 0x2c5418b)` reaches that instruction boundary. The FDE itself is at `0x118cc40`.

At `0x64768f0` (file offset `0x64748f0`), an `R_X86_64_RELATIVE` relocation points to `0x432b6f` in `.rodata`. The next 16 bytes, `13000000000000007d00000025000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 125 and 37. The string's normalized suffix matches `l1/spot_meta.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c53e22` is `0x2c540a9` and the fallthrough is `0x2c53e28`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rbp, qword ptr [r14 + 0xb8]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c53e1b` | `493baeb8000000` | `cmp rbp, qword ptr [r14 + 0xb8]` |
| `0x2c53e22` | `0f8381020000` | `jae 0x2c540a9` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 59291514 added to `0x2c540b6` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c540b0` | `ff157ab78803` | `call qword ptr [rip + 0x388b77a]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64768f0 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c53850 --stop-address=0x2c540b6 "$target"
od -An -tx1 -j 105335032 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b6f --stop-address=0x432b82 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d41288203`), re-decoding lands at `0x64768f1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 125, column 37. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
