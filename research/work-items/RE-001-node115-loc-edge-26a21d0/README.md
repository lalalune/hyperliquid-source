# RE-001: map node #115 base/u.rs:531 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x26a21d0` (file offset `0x26a11d0`), `488d15d153d903` decodes as `lea rdx, [rip + 0x3d953d1]`. Adding the signed displacement `64574417` to the next instruction VA `0x26a21d7` yields `0x64375a8`. The decode from the start of FDE range `[0x26a21b0, 0x26a23ca)` reaches that instruction boundary. The FDE itself is at `0x112c464`.

At `0x64375a8` (file offset `0x64355a8`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d000000000000001302000009000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 531 and 9. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x26a21c1` is `0x26a223e` and the fallthrough is `0x26a21c3`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test edx, edx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x26a21bf` | `85d2` | `test edx, edx` |
| `0x26a21c1` | `747b` | `je 0x26a223e` |
| `0x26a21c3` | `4989f7` | `mov r15, rsi` |
| `0x26a21c6` | `c644240e00` | `mov byte ptr [rsp + 0xe], 0` |
| `0x26a21cb` | `c644240f00` | `mov byte ptr [rsp + 0xf], 0` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed call displacement -2421286 added to `0x26a21e6` gives `0x2452fc0`. The target's FDE at `0x110e2e8` describes `[0x2452fc0, 0x24531be)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x26a21d7` | `488d7c240e` | `lea rdi, [rsp + 0xe]` |
| `0x26a21dc` | `488d74240f` | `lea rsi, [rsp + 0xf]` |
| `0x26a21e1` | `e8da0ddbff` | `call 0x2452fc0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64375a8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x26a21b0 --stop-address=0x26a21e6 "$target"
od -An -tx1 -j 105076144 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15d253d903`), re-decoding lands at `0x64375a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 531, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
