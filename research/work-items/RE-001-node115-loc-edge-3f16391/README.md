# RE-001: map node #115 base/l1_map/entry.rs:64 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/l1_map/entry.rs` as an embedded path. At ELF VA `0x3f16391` (file offset `0x3f15391`), `488d15f0785602` decodes as `lea rdx, [rip + 0x25678f0]`. Adding the signed displacement `39221488` to the next instruction VA `0x3f16398` yields `0x647dc88`. The decode from the start of FDE range `[0x3f161e0, 0x3f163a3)` reaches that instruction boundary. The FDE itself is at `0xe73138`.

At `0x647dc88` (file offset `0x647bc88`), an `R_X86_64_RELATIVE` relocation points to `0x4402cd` in `.rodata`. The next 16 bytes, `18000000000000004000000011000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 64 and 17. The string's normalized suffix matches `base/l1_map/entry.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x3f16350` is `0x3f1638a` and the fallthrough is `0x3f16352`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rbx, qword ptr [r14 + 0x18]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3f1634c` | `493b5e18` | `cmp rbx, qword ptr [r14 + 0x18]` |
| `0x3f16350` | `7338` | `jae 0x3f1638a` |
| `0x3f1638a` | `488d3dbcfe8afc` | `lea rdi, [rip - 0x3750144]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 39621581 added to `0x3f163a3` gives the relocation slot `0x64df770`. Its symbol-zero RELATIVE addend is `0x1680bd0`. The target's FDE at `0xcc2fec` describes `[0x1680bd0, 0x1680c04)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3f16398` | `be14000000` | `mov esi, 0x14` |
| `0x3f1639d` | `ff15cd935c02` | `call qword ptr [rip + 0x25c93cd]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*647dc88 '
readelf -rW "$target" | grep -i '0*64df770 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x3f161e0 --stop-address=0x3f163a3 "$target"
od -An -tx1 -j 105364624 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4402cd --stop-address=0x4402e5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15f1785602`), re-decoding lands at `0x647dc89`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 64, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
