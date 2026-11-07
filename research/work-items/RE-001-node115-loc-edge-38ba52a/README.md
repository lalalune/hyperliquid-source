# RE-001: map node #115 l1/asset/pdi.rs:32 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/asset/pdi.rs` as an embedded path. At ELF VA `0x38ba52a` (file offset `0x38b952a`), `488d3dc73ebb02` decodes as `lea rdi, [rip + 0x2bb3ec7]`. Adding the signed displacement `45825735` to the next instruction VA `0x38ba531` yields `0x646e3f8`. The decode from the start of FDE range `[0x38b9f40, 0x38ba5c9)` reaches that instruction boundary. The FDE itself is at `0x121dee0`.

At `0x646e3f8` (file offset `0x646c3f8`), an `R_X86_64_RELATIVE` relocation points to `0x448f4e` in `.rodata`. The next 16 bytes, `1300000000000000200000000e000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 32 and 14. The string's normalized suffix matches `l1/asset/pdi.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x38ba07e` is `0x38ba52a` and the fallthrough is `0x38ba084`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rdi, r8`. The recorded edge is selected when the `jb` predicate (`CF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38ba07b` | `4c39c7` | `cmp rdi, r8` |
| `0x38ba07e` | `0f82a6040000` | `jb 0x38ba52a` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 46288873 added to `0x38ba537` gives the relocation slot `0x64df520`. Its symbol-zero RELATIVE addend is `0x1681da0`. The target's FDE at `0xcc3294` describes `[0x1681da0, 0x1681db9)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38ba531` | `ff15e94fc202` | `call qword ptr [rip + 0x2c24fe9]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*646e3f8 '
readelf -rW "$target" | grep -i '0*64df520 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x38b9f40 --stop-address=0x38ba537 "$target"
od -An -tx1 -j 105300992 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448f4e --stop-address=0x448f61 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3dc83ebb02`), re-decoding lands at `0x646e3f9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 32, column 14. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
