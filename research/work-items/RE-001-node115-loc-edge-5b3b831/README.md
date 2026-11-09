# RE-001: map node #115 l1/asset/pdi.rs:32 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/asset/pdi.rs` as an embedded path. At ELF VA `0x5b3b831` (file offset `0x5b3a831`), `488d3d00ee9600` decodes as `lea rdi, [rip + 0x96ee00]`. Adding the signed displacement `9891328` to the next instruction VA `0x5b3b838` yields `0x64aa638`. The decode from the start of FDE range `[0x5b3aea0, 0x5b3b926)` reaches that instruction boundary. The FDE itself is at `0x13bb500`.

At `0x64aa638` (file offset `0x64a8638`), an `R_X86_64_RELATIVE` relocation points to `0x448f4e` in `.rodata`. The next 16 bytes, `1300000000000000200000000e000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 32 and 14. The string's normalized suffix matches `l1/asset/pdi.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5b3b13f` is `0x5b3b831` and the fallthrough is `0x5b3b145`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rsi, rcx`. The recorded edge is selected when the `jb` predicate (`CF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5b3b13c` | `4839ce` | `cmp rsi, rcx` |
| `0x5b3b13f` | `0f82ec060000` | `jb 0x5b3b831` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 10108130 added to `0x5b3b83e` gives the relocation slot `0x64df520`. Its symbol-zero RELATIVE addend is `0x1681da0`. The target's FDE at `0xcc3294` describes `[0x1681da0, 0x1681db9)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5b3b838` | `ff15e23c9a00` | `call qword ptr [rip + 0x9a3ce2]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa638 '
readelf -rW "$target" | grep -i '0*64df520 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5b3aea0 --stop-address=0x5b3b83e "$target"
od -An -tx1 -j 105547328 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448f4e --stop-address=0x448f61 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d01ee9600`), re-decoding lands at `0x64aa639`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 32, column 14. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
