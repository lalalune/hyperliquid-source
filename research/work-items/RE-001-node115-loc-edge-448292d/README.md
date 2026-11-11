# RE-001: map node #115 l1/qtys/mod.rs:847 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/qtys/mod.rs` as an embedded path. At ELF VA `0x448292d` (file offset `0x448192d`), `4c8d0504910002` decodes as `lea r8, [rip + 0x2009104]`. Adding the signed displacement `33591556` to the next instruction VA `0x4482934` yields `0x648ba38`. The decode from the start of FDE range `[0x4482830, 0x4482944)` reaches that instruction boundary. The FDE itself is at `0xebc82c`.

At `0x648ba38` (file offset `0x6489a38`), an `R_X86_64_RELATIVE` relocation points to `0x435910` in `.rodata`. The next 16 bytes, `12000000000000004f03000001000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 847 and 1. The string's normalized suffix matches `l1/qtys/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4482889` is `0x448291f` and the fallthrough is `0x448288f`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r13, r13`. The recorded edge is selected when the `js` predicate (`SF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4482886` | `4d85ed` | `test r13, r13` |
| `0x4482889` | `0f8890000000` | `js 0x448291f` |
| `0x448291f` | `488d3dec0835fc` | `lea rdi, [rip - 0x3caf714]` |
| `0x4482926` | `488d0d6b9c0002` | `lea rcx, [rip + 0x2009c6b]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 33934684 added to `0x4482944` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4482934` | `488d542407` | `lea rdx, [rsp + 7]` |
| `0x4482939` | `be2b000000` | `mov esi, 0x2b` |
| `0x448293e` | `ff155ccd0502` | `call qword ptr [rip + 0x205cd5c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648ba38 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4482830 --stop-address=0x4482944 "$target"
od -An -tx1 -j 105421376 -N 16 "$target"
objdump -s -j .rodata --start-address=0x435910 --stop-address=0x435922 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0505910002`), re-decoding lands at `0x648ba39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 847, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
