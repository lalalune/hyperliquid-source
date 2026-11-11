# RE-001: map node #115 base/l1_map/entry.rs:210 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/l1_map/entry.rs` as an embedded path. At ELF VA `0x3f1a3e6` (file offset `0x3f193e6`), `488d15b3385602` decodes as `lea rdx, [rip + 0x25638b3]`. Adding the signed displacement `39205043` to the next instruction VA `0x3f1a3ed` yields `0x647dca0`. The decode from the start of FDE range `[0x3f1a2e0, 0x3f1a3f8)` reaches that instruction boundary. The FDE itself is at `0xe73d14`.

At `0x647dca0` (file offset `0x647bca0`), an `R_X86_64_RELATIVE` relocation points to `0x4402cd` in `.rodata`. The next 16 bytes, `1800000000000000d200000027000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 210 and 39. The string's normalized suffix matches `base/l1_map/entry.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x3f1a310` is `0x3f1a3df` and the fallthrough is `0x3f1a316`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r15, r8`. The recorded edge is selected when the `jbe` predicate (`CF = 1 or ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3f1a30d` | `4d39c7` | `cmp r15, r8` |
| `0x3f1a310` | `0f86c9000000` | `jbe 0x3f1a3df` |
| `0x3f1a3df` | `488d3d7bbe8afc` | `lea rdi, [rip - 0x3754185]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 39605112 added to `0x3f1a3f8` gives the relocation slot `0x64df770`. Its symbol-zero RELATIVE addend is `0x1680bd0`. The target's FDE at `0xcc2fec` describes `[0x1680bd0, 0x1680c04)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3f1a3ed` | `be14000000` | `mov esi, 0x14` |
| `0x3f1a3f2` | `ff1578535c02` | `call qword ptr [rip + 0x25c5378]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*647dca0 '
readelf -rW "$target" | grep -i '0*64df770 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x3f1a2e0 --stop-address=0x3f1a3f8 "$target"
od -An -tx1 -j 105364648 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4402cd --stop-address=0x4402e5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15b4385602`), re-decoding lands at `0x647dca1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 210, column 39. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
