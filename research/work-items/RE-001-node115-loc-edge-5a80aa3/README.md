# RE-001: map node #115 base/lu.rs:35 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/lu.rs` as an embedded path. At ELF VA `0x5a80aa3` (file offset `0x5a7faa3`), `488d3d9e76a300` decodes as `lea rdi, [rip + 0xa3769e]`. Adding the signed displacement `10712734` to the next instruction VA `0x5a80aaa` yields `0x64b8148`. The decode from the start of FDE range `[0x5a806f0, 0x5a81584)` reaches that instruction boundary. The FDE itself is at `0x13aa7bc`.

At `0x64b8148` (file offset `0x64b6148`), an `R_X86_64_RELATIVE` relocation points to `0x4326c1` in `.rodata`. The next 16 bytes, `0e00000000000000230000000f000000`, decode as a little-endian 64-bit length of 14 and two 32-bit values, 35 and 15. The string's normalized suffix matches `base/lu.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5a80a7c` is `0x5a80aa3` and the fallthrough is `0x5a80a7e`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp ebp, 0x3b9ac9ff`. The recorded edge is selected when the `jbe` predicate (`CF = 1 or ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a80a76` | `81fdffc99a3b` | `cmp ebp, 0x3b9ac9ff` |
| `0x5a80a7c` | `7625` | `jbe 0x5a80aa3` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 10878360 added to `0x5a80ab0` gives the relocation slot `0x64e0848`. Its symbol-zero RELATIVE addend is `0x5cf2b50`. The target's FDE at `0xfe6c50` describes `[0x5cf2b50, 0x5cf2c34)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a80aaa` | `ff1598fda500` | `call qword ptr [rip + 0xa5fd98]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b8148 '
readelf -rW "$target" | grep -i '0*64e0848 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a806f0 --stop-address=0x5a80ab0 "$target"
od -An -tx1 -j 105603408 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4326c1 --stop-address=0x4326cf "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d9f76a300`), re-decoding lands at `0x64b8149`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 35, column 15. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
