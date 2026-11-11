# RE-001: map node #115 l1/vault/mod.rs:618 conditional call edge

- Component allocation: `vaults`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/vault/mod.rs` as an embedded path. At ELF VA `0x44abfa0` (file offset `0x44aafa0`), `488d3db101fe01` decodes as `lea rdi, [rip + 0x1fe01b1]`. Adding the signed displacement `33423793` to the next instruction VA `0x44abfa7` yields `0x648c158`. The decode from the start of FDE range `[0x44ab4a0, 0x44abfaf)` reaches that instruction boundary. The FDE itself is at `0x12a6324`.

At `0x648c158` (file offset `0x648a158`), an `R_X86_64_RELATIVE` relocation points to `0x43e326` in `.rodata`. The next 16 bytes, `13000000000000006a0200005d000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 618 and 93. The string's normalized suffix matches `l1/vault/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x44abb69` is `0x44abfa0` and the fallthrough is `0x44abb6f`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test cl, cl`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44abb67` | `84c9` | `test cl, cl` |
| `0x44abb69` | `0f8531040000` | `jne 0x44abfa0` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 33765507 added to `0x44abfad` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44abfa7` | `ff1583380302` | `call qword ptr [rip + 0x2033883]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648c158 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x44ab4a0 --stop-address=0x44abfad "$target"
od -An -tx1 -j 105423200 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43e326 --stop-address=0x43e339 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3db201fe01`), re-decoding lands at `0x648c159`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 618, column 93. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
