# RE-001: map node #115 l1/qtys/mod.rs:848 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/qtys/mod.rs` as an embedded path. At ELF VA `0x44841ba` (file offset `0x44831ba`), `4c8d052f780002` decodes as `lea r8, [rip + 0x200782f]`. Adding the signed displacement `33585199` to the next instruction VA `0x44841c1` yields `0x648b9f0`. The decode from the start of FDE range `[0x4483bb0, 0x448446f)` reaches that instruction boundary. The FDE itself is at `0x12a564c`.

At `0x648b9f0` (file offset `0x64899f0`), an `R_X86_64_RELATIVE` relocation points to `0x435910` in `.rodata`. The next 16 bytes, `12000000000000005003000001000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 848 and 1. The string's normalized suffix matches `l1/qtys/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4483bc8` is `0x44841ac` and the fallthrough is `0x4483bce`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `js` predicate (`SF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4483bc5` | `4885c0` | `test rax, rax` |
| `0x4483bc8` | `0f88de050000` | `js 0x44841ac` |
| `0x44841ac` | `488d3d5ff034fc` | `lea rdi, [rip - 0x3cb0fa1]` |
| `0x44841b3` | `488d0dde830002` | `lea rcx, [rip + 0x20083de]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 33928399 added to `0x44841d1` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44841c1` | `488d542406` | `lea rdx, [rsp + 6]` |
| `0x44841c6` | `be2b000000` | `mov esi, 0x2b` |
| `0x44841cb` | `ff15cfb40502` | `call qword ptr [rip + 0x205b4cf]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b9f0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4483bb0 --stop-address=0x44841d1 "$target"
od -An -tx1 -j 105421304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x435910 --stop-address=0x435922 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0530780002`), re-decoding lands at `0x648b9f1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 848, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
