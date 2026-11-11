# RE-001: map node #115 base/u.rs:531 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x2701414` (file offset `0x2700414`), `488d158d61d303` decodes as `lea rdx, [rip + 0x3d3618d]`. Adding the signed displacement `64184717` to the next instruction VA `0x270141b` yields `0x64375a8`. The decode from the start of FDE range `[0x27013e0, 0x2701765)` reaches that instruction boundary. The FDE itself is at `0x1132c58`.

At `0x64375a8` (file offset `0x64355a8`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d000000000000001302000009000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 531 and 9. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2701408` is `0x2701486` and the fallthrough is `0x270140a`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test ebp, ebp`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2701406` | `85ed` | `test ebp, ebp` |
| `0x2701408` | `747c` | `je 0x2701486` |
| `0x270140a` | `c644240700` | `mov byte ptr [rsp + 7], 0` |
| `0x270140f` | `c644244800` | `mov byte ptr [rsp + 0x48], 0` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed call displacement -2809962 added to `0x270142a` gives `0x24533c0`. The target's FDE at `0x110e350` describes `[0x24533c0, 0x24535be)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x270141b` | `488d7c2407` | `lea rdi, [rsp + 7]` |
| `0x2701420` | `488d742448` | `lea rsi, [rsp + 0x48]` |
| `0x2701425` | `e8961fd5ff` | `call 0x24533c0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64375a8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x27013e0 --stop-address=0x270142a "$target"
od -An -tx1 -j 105076144 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d158e61d303`), re-decoding lands at `0x64375a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 531, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
