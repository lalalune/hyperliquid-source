# RE-001: map node #115 l1/book/book/mod.rs:1148 conditional call edge

- Component allocation: `orderbook`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/book/book/mod.rs` as an embedded path. At ELF VA `0x50bd1dd` (file offset `0x50bc1dd`), `488d3d9c403e01` decodes as `lea rdi, [rip + 0x13e409c]`. Adding the signed displacement `20856988` to the next instruction VA `0x50bd1e4` yields `0x64a1280`. The decode from the start of FDE range `[0x50bcc80, 0x50bd235)` reaches that instruction boundary. The FDE itself is at `0x1319c34`.

At `0x64a1280` (file offset `0x649f280`), an `R_X86_64_RELATIVE` relocation points to `0x438bcf` in `.rodata`. The next 16 bytes, `17000000000000007c0400004f000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 1148 and 79. The string's normalized suffix matches `l1/book/book/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x50bcdde` is `0x50bd1dd` and the fallthrough is `0x50bcde4`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x50bcddb` | `4885c0` | `test rax, rax` |
| `0x50bcdde` | `0f84f9030000` | `je 0x50bd1dd` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 21112390 added to `0x50bd1ea` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x50bd1e4` | `ff1546264201` | `call qword ptr [rip + 0x1422646]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64a1280 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x50bcc80 --stop-address=0x50bd1ea "$target"
od -An -tx1 -j 105509512 -N 16 "$target"
objdump -s -j .rodata --start-address=0x438bcf --stop-address=0x438be6 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d9d403e01`), re-decoding lands at `0x64a1281`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 1148, column 79. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
