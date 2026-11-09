# RE-001: map node #115 l1/spot_meta.rs:1206 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/spot_meta.rs` as an embedded path. At ELF VA `0x3bf52b2` (file offset `0x3bf42b2`), `488d3d8f178802` decodes as `lea rdi, [rip + 0x288178f]`. Adding the signed displacement `42473359` to the next instruction VA `0x3bf52b9` yields `0x6476a48`. The decode from the start of FDE range `[0x3bf5120, 0x3bf5fb3)` reaches that instruction boundary. The FDE itself is at `0x12425dc`.

At `0x6476a48` (file offset `0x6474a48`), an `R_X86_64_RELATIVE` relocation points to `0x432b6f` in `.rodata`. The next 16 bytes, `1300000000000000b604000039000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 1206 and 57. The string's normalized suffix matches `l1/spot_meta.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x3bf5295` is `0x3bf52b2` and the fallthrough is `0x3bf5297`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test dl, 0x10`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3bf5292` | `f6c210` | `test dl, 0x10` |
| `0x3bf5295` | `741b` | `je 0x3bf52b2` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 42902897 added to `0x3bf52bf` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3bf52b9` | `ff1571a58e02` | `call qword ptr [rip + 0x28ea571]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6476a48 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x3bf5120 --stop-address=0x3bf52bf "$target"
od -An -tx1 -j 105335376 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b6f --stop-address=0x432b82 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d90178802`), re-decoding lands at `0x6476a49`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 1206, column 57. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
