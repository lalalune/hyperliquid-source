# RE-001: map node #115 base/l1_map/entry.rs:64 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/l1_map/entry.rs` as an embedded path. At ELF VA `0x3f170b8` (file offset `0x3f160b8`), `488d15c96b5602` decodes as `lea rdx, [rip + 0x2566bc9]`. Adding the signed displacement `39218121` to the next instruction VA `0x3f170bf` yields `0x647dc88`. The decode from the start of FDE range `[0x3f16f70, 0x3f170ca)` reaches that instruction boundary. The FDE itself is at `0xe73384`.

At `0x647dc88` (file offset `0x647bc88`), an `R_X86_64_RELATIVE` relocation points to `0x4402cd` in `.rodata`. The next 16 bytes, `18000000000000004000000011000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 64 and 17. The string's normalized suffix matches `base/l1_map/entry.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x3f1707b` is `0x3f170b1` and the fallthrough is `0x3f1707d`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rbx, qword ptr [r14 + 0x18]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3f17077` | `493b5e18` | `cmp rbx, qword ptr [r14 + 0x18]` |
| `0x3f1707b` | `7334` | `jae 0x3f170b1` |
| `0x3f170b1` | `488d3d95f18afc` | `lea rdi, [rip - 0x3750e6b]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 39618214 added to `0x3f170ca` gives the relocation slot `0x64df770`. Its symbol-zero RELATIVE addend is `0x1680bd0`. The target's FDE at `0xcc2fec` describes `[0x1680bd0, 0x1680c04)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3f170bf` | `be14000000` | `mov esi, 0x14` |
| `0x3f170c4` | `ff15a6865c02` | `call qword ptr [rip + 0x25c86a6]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*647dc88 '
readelf -rW "$target" | grep -i '0*64df770 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x3f16f70 --stop-address=0x3f170ca "$target"
od -An -tx1 -j 105364624 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4402cd --stop-address=0x4402e5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15ca6b5602`), re-decoding lands at `0x647dc89`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 64, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
