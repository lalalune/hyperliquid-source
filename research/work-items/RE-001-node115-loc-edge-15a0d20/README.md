# RE-001: map node #115 base/lu.rs:35 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/lu.rs` as an embedded path. At ELF VA `0x15a0d20` (file offset `0x159fd20`), `488d3d79ede504` decodes as `lea rdi, [rip + 0x4e5ed79]`. Adding the signed displacement `82177401` to the next instruction VA `0x15a0d27` yields `0x63ffaa0`. The decode from the start of FDE range `[0x15a0890, 0x15a12d4)` reaches that instruction boundary. The FDE itself is at `0x1055134`.

At `0x63ffaa0` (file offset `0x63fdaa0`), an `R_X86_64_RELATIVE` relocation points to `0x4326c1` in `.rodata`. The next 16 bytes, `0e00000000000000230000000f000000`, decode as a little-endian 64-bit length of 14 and two 32-bit values, 35 and 15. The string's normalized suffix matches `base/lu.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x15a0cfc` is `0x15a0d20` and the fallthrough is `0x15a0cfe`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp ebp, 0x3b9ac9ff`. The recorded edge is selected when the `jbe` predicate (`CF = 1 or ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15a0cf6` | `81fdffc99a3b` | `cmp ebp, 0x3b9ac9ff` |
| `0x15a0cfc` | `7622` | `jbe 0x15a0d20` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 83098395 added to `0x15a0d2d` gives the relocation slot `0x64e0848`. Its symbol-zero RELATIVE addend is `0x5cf2b50`. The target's FDE at `0xfe6c50` describes `[0x5cf2b50, 0x5cf2c34)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15a0d27` | `ff151bfbf304` | `call qword ptr [rip + 0x4f3fb1b]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63ffaa0 '
readelf -rW "$target" | grep -i '0*64e0848 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x15a0890 --stop-address=0x15a0d2d "$target"
od -An -tx1 -j 104848040 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4326c1 --stop-address=0x4326cf "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d7aede504`), re-decoding lands at `0x63ffaa1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 35, column 15. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
