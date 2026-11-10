# RE-001: map node #115 base/l1_map/entry.rs:64 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/l1_map/entry.rs` as an embedded path. At ELF VA `0x24239c6` (file offset `0x24229c6`), `488d1523c10004` decodes as `lea rdx, [rip + 0x400c123]`. Adding the signed displacement `67158307` to the next instruction VA `0x24239cd` yields `0x642faf0`. The decode from the start of FDE range `[0x2423900, 0x24239d8)` reaches that instruction boundary. The FDE itself is at `0xd0c60c`.

At `0x642faf0` (file offset `0x642daf0`), an `R_X86_64_RELATIVE` relocation points to `0x4402cd` in `.rodata`. The next 16 bytes, `18000000000000004000000011000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 64 and 17. The string's normalized suffix matches `base/l1_map/entry.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2423988` is `0x24239bf` and the fallthrough is `0x242398a`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rbx, qword ptr [r14 + 0x18]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2423984` | `493b5e18` | `cmp rbx, qword ptr [r14 + 0x18]` |
| `0x2423988` | `7335` | `jae 0x24239bf` |
| `0x24239bf` | `488d3d99a71cfe` | `lea rdi, [rip - 0x1e35867]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 67878296 added to `0x24239d8` gives the relocation slot `0x64df770`. Its symbol-zero RELATIVE addend is `0x1680bd0`. The target's FDE at `0xcc2fec` describes `[0x1680bd0, 0x1680c04)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x24239cd` | `be14000000` | `mov esi, 0x14` |
| `0x24239d2` | `ff1598bd0b04` | `call qword ptr [rip + 0x40bbd98]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642faf0 '
readelf -rW "$target" | grep -i '0*64df770 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2423900 --stop-address=0x24239d8 "$target"
od -An -tx1 -j 105044728 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4402cd --stop-address=0x4402e5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1524c10004`), re-decoding lands at `0x642faf1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 64, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
