# RE-001: map node #115 l1/vault/mod.rs:745 conditional call edge

- Component allocation: `vaults`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/vault/mod.rs` as an embedded path. At ELF VA `0x44b04a7` (file offset `0x44af4a7`), `488d3d0abdfd01` decodes as `lea rdi, [rip + 0x1fdbd0a]`. Adding the signed displacement `33406218` to the next instruction VA `0x44b04ae` yields `0x648c1b8`. The decode from the start of FDE range `[0x44af2f0, 0x44b04b6)` reaches that instruction boundary. The FDE itself is at `0x12a6570`.

At `0x648c1b8` (file offset `0x648a1b8`), an `R_X86_64_RELATIVE` relocation points to `0x43e326` in `.rodata`. The next 16 bytes, `1300000000000000e90200003a000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 745 and 58. The string's normalized suffix matches `l1/vault/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x44afcf9` is `0x44b04a7` and the fallthrough is `0x44afcff`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rbx, rbx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44afcf6` | `4885db` | `test rbx, rbx` |
| `0x44afcf9` | `0f84a8070000` | `je 0x44b04a7` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 33747836 added to `0x44b04b4` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44b04ae` | `ff157cf30202` | `call qword ptr [rip + 0x202f37c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648c1b8 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x44af2f0 --stop-address=0x44b04b4 "$target"
od -An -tx1 -j 105423296 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43e326 --stop-address=0x43e339 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d0bbdfd01`), re-decoding lands at `0x648c1b9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 745, column 58. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
